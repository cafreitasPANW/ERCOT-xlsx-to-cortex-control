#!/usr/bin/env python3
"""Build a Cortex Cloud custom compliance standard from a spreadsheet of control names.

Given an xlsx with one control name per row, a *source* built-in standard and a *target*
custom standard, the script:

  1. matches every spreadsheet name to a control of the source standard, ignoring leading
     identifiers / level tags ("1.1.1", "A.5.1", "AC-2", "(L1)", ...) on both sides and
     tolerating small textual differences (customised thresholds etc.);
  2. clones each matched built-in control as a custom control named after the spreadsheet
     row (plus optional prefix/suffix) -- the public API only allows custom controls in a
     custom standard;
  3. mirrors the built-in control's compliance rules onto the clone (get_control ->
     add_rules_to_control);
  4. attaches all clones to the target standard.

Nothing is specific to one standard: the built-in catalog is scanned once (and cached on
disk), the scannable-asset enum names the rules API expects are discovered per run, and
every run is idempotent. Use --dry-run to only match and report.

Credentials: --fqdn/--api-key-id/--api-key, or CORTEX_FQDN / CORTEX_API_KEY_ID / CORTEX_API_KEY from the
environment or a `.env` file in the working directory (see .env.example).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable, Iterator

import openpyxl
import requests

LOG = logging.getLogger("xlsx_to_cortex")

PAGE_SIZE = 100  # API hard limit
CACHE_VERSION = 2
PROBE_CONTROL_ID = "00000000000000000000000000000000"  # never exists; request validation runs first

# Leading identifier such as `1.1.1`, `18.10.57.2.2`, `A.5.1`, `AC-2`, `CC6.1`, `[1.2]`, optionally
# followed by a separator. Requires a digit so words like `2FA` are left alone.
IDENT_RE = re.compile(r"^\s*[\[\(]?[A-Za-z]{0,6}[.\-]?\d+(?:[.\-]\w+)*[\]\)]?(?=\s|$|[-–—:.|])\s*(?:[-–—:.|]\s*)?")
# Leading short tag such as `(L1)`, `(L2)`, `(NG)`, `(BL)`, `(MS)`.
TAG_RE = re.compile(r"^\s*\([A-Za-z0-9+/ ]{1,6}\)\s*(?:[-–—:|]\s*)?")
# Trailing CIS scoring tags that differ between benchmark versions.
TRAILING_TAG_RE = re.compile(r"\s*\((?:automated|manual|scored|not scored)\)\s*$", re.IGNORECASE)
QUOTED_RE = re.compile(r"'([^']+)'")
DESC_MARKER_RE = re.compile(r"\s*##[^#]*##\s*$")
SMART_QUOTES = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": "'", "\u201d": "'", '"': "'"})
RULE_SEVERITIES = ("critical", "high", "medium", "low")
SETTING_BONUS = 0.05
SETTING_PENALTY = 0.15


# --------------------------------------------------------------------------- API


class CortexAPIError(RuntimeError):
    def __init__(self, path: str, status: int, body: str):
        super().__init__(f"{path} -> HTTP {status}: {body}")
        self.status = status
        self.body = body


class CortexClient:
    def __init__(self, fqdn: str, key_id: str, key: str, timeout: int = 60, retries: int = 4):
        fqdn = fqdn.strip().rstrip("/")
        if not fqdn.startswith("http"):
            fqdn = "https://" + fqdn
        self.base = fqdn
        self.headers = {"x-xdr-auth-id": str(key_id), "Authorization": key, "Content-Type": "application/json"}
        self.timeout = timeout
        self.retries = retries
        self._local = threading.local()

    @property
    def session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            self._local.session = requests.Session()
            self._local.session.headers.update(self.headers)
        return self._local.session

    def _post(self, path: str, request_data: dict, timeout: int | None = None, retries: int | None = None) -> dict:
        url = f"{self.base}/public_api/v1/compliance/{path}"
        timeout = timeout or self.timeout
        retries = retries or self.retries
        delay = 2.0
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.post(url, json={"request_data": request_data}, timeout=timeout)
            except requests.RequestException as exc:
                if attempt < retries:
                    LOG.warning("%s failed (%s), retrying in %.0fs (%d/%d)", path, exc.__class__.__name__, delay, attempt, retries)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise CortexAPIError(path, 0, f"{exc.__class__.__name__}: {exc}") from exc
            if resp.status_code == 200:
                return resp.json().get("reply", {})
            # Several business errors come back as HTTP 500; none of these are transient.
            permanent = any(m in resp.text for m in ("already exists", "already associated", "doesnt exist", "doesn't exist"))
            retryable = resp.status_code == 429 or (resp.status_code >= 500 and not permanent)
            if retryable and attempt < retries:
                LOG.warning("%s returned %s, retrying in %.0fs (%d/%d)", path, resp.status_code, delay, attempt, retries)
                time.sleep(delay)
                delay *= 2
                continue
            raise CortexAPIError(path, resp.status_code, resp.text)
        raise CortexAPIError(path, 0, "exhausted retries")

    def _controls_page(self, filters: list[dict], start: int) -> dict:
        return self._post(
            "get_controls",
            {"filters": filters, "sort": {"field": "id", "keyword": "asc"}, "search_from": start, "search_to": start + PAGE_SIZE},
        )

    def iter_controls(self, filters: list[dict]) -> Iterator[dict]:
        """Page through get_controls sequentially, de-duplicating by CONTROL_ID."""
        seen: set[str] = set()
        start = 0
        while True:
            reply = self._controls_page(filters, start)
            controls = reply.get("controls") or []
            for ctrl in controls:
                cid = ctrl.get("CONTROL_ID")
                if cid and cid not in seen:
                    seen.add(cid)
                    yield ctrl
            start += PAGE_SIZE
            if not controls or start >= int(reply.get("result_count") or 0):
                return

    def fetch_controls(self, filters: list[dict], workers: int, label: str) -> list[dict]:
        """Fetch every control matching `filters`, paging in parallel."""
        first = self._controls_page(filters, 0)
        total = int(first.get("result_count") or 0)
        pages = list(range(PAGE_SIZE, total, PAGE_SIZE))
        LOG.info("Fetching %d %s controls (%d pages, %d workers) ...", total, label, len(pages) + 1, workers)
        by_id: dict[str, dict] = {c["CONTROL_ID"]: c for c in first.get("controls") or []}
        done = 1
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for reply in pool.map(lambda s: self._controls_page(filters, s), pages):
                for c in reply.get("controls") or []:
                    by_id.setdefault(c["CONTROL_ID"], c)
                done += 1
                if done % 25 == 0:
                    LOG.info("  %d/%d pages", done, len(pages) + 1)
        return list(by_id.values())

    def find_standard(self, name: str) -> dict | None:
        reply = self._post(
            "get_standards",
            {"filters": [{"field": "name", "operator": "eq", "value": name}], "search_from": 0, "search_to": PAGE_SIZE},
        )
        matches = [s for s in reply.get("standards") or [] if s.get("name") == name]
        if len(matches) > 1:
            raise SystemExit(f"Standard name '{name}' is ambiguous: {[s['id'] for s in matches]}")
        return matches[0] if matches else None

    def get_standard(self, standard_id: str) -> dict:
        reply = self._post("get_standard", {"id": standard_id})
        standards = reply.get("standard") or []
        if not standards:
            raise SystemExit(f"Standard id {standard_id} not found.")
        return standards[0]

    def add_standard(self, name: str, description: str) -> None:
        reply = self._post("add_standard", {"standard_name": name, "description": description})
        if not reply.get("success"):
            raise CortexAPIError("add_standard", 200, str(reply))

    def get_control(self, control_id: str) -> dict:
        """Full control record (get_control by ID), including COMPLIANCE_RULES."""
        reply = self._post("get_control", {"id": control_id})
        controls = reply.get("control") or []
        if not controls:
            raise CortexAPIError("get_control", 404, f"control {control_id} not found")
        return controls[0]

    def add_control(self, name: str, description: str, category: str, subcategory: str | None) -> str:
        body = {"control_name": name, "description": description, "category": category}
        if subcategory:
            body["subcategory"] = subcategory
        reply = self._post("add_control", body)
        if not reply.get("success"):
            raise CortexAPIError("add_control", 200, str(reply))
        control_id = reply.get("control_id")
        if not control_id:
            found = self.lookup_control_by_name(name)
            if not found:
                raise CortexAPIError("add_control", 200, f"created but could not resolve id for '{name}'")
            control_id = found["CONTROL_ID"]
        return control_id

    def edit_control(self, control_id: str, description: str, category: str, subcategory: str | None) -> None:
        body = {"id": control_id, "description": description, "category": category}
        if subcategory:
            body["subcategory"] = subcategory
        reply = self._post("edit_control", body)
        if not reply.get("success"):
            raise CortexAPIError("edit_control", 200, str(reply))

    def lookup_control_by_name(self, name: str) -> dict | None:
        found = [c for c in self.iter_controls([{"field": "name", "operator": "eq", "value": name}]) if c.get("CONTROL_NAME") == name]
        return found[0] if found else None

    def add_rules_to_control(self, control_id: str, rules: list[dict]) -> None:
        reply = self._post("add_rules_to_control", {"control_id": control_id, "rules": rules})
        if not reply.get("success"):
            raise CortexAPIError("add_rules_to_control", 200, str(reply))

    def delete_rules_from_control(self, control_id: str, rules_ids: list[str]) -> None:
        reply = self._post("delete_rules_from_control", {"control_id": control_id, "rules_ids": rules_ids})
        if not reply.get("success"):
            raise CortexAPIError("delete_rules_from_control", 200, str(reply))

    def get_controls_by_id(self, control_ids: Iterable[str], workers: int) -> dict[str, dict]:
        ids = list(dict.fromkeys(control_ids))
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            return dict(zip(ids, pool.map(self.get_control, ids)))

    def edit_standard_controls(self, standard_id: str, controls_ids: list[str]) -> None:
        # Large control lists take well over a minute server-side and the gateway may time out
        # even though the change is applied, so do not retry blindly; the caller verifies.
        reply = self._post("edit_standard", {"id": standard_id, "controls_ids": controls_ids}, timeout=180, retries=1)
        if not reply.get("success"):
            raise CortexAPIError("edit_standard", 200, str(reply))

    def attach_controls(self, standard_id: str, existing_ids: list[str], new_ids: list[str], batch_size: int = 50,
                        verify_attempts: int = 6, verify_delay: float = 10.0) -> list[str]:
        """Attach `new_ids` in batches, confirming each batch through get_standard. Returns ids still missing."""
        current = list(existing_ids)
        for start in range(0, len(new_ids), batch_size):
            desired = current + new_ids[start:start + batch_size]
            LOG.info("edit_standard: %d -> %d controls", len(current), len(desired))
            try:
                self.edit_standard_controls(standard_id, desired)
            except CortexAPIError as err:
                LOG.warning("edit_standard did not confirm (%s); verifying server state", err.body[:120].replace("\n", " "))
            attached: set[str] = set()
            for attempt in range(verify_attempts):
                attached = set(self.get_standard(standard_id).get("controls_ids") or [])
                if set(desired) <= attached:
                    break
                LOG.info("verification %d/%d: %d of %d attached, waiting %.0fs", attempt + 1, verify_attempts,
                         len(attached & set(desired)), len(desired), verify_delay)
                time.sleep(verify_delay)
            else:
                return [cid for cid in new_ids if cid not in attached]
            current = desired
        return []


# ------------------------------------------------------------------ catalog


def compact_control(ctrl: dict) -> dict:
    """The subset of a control record the script needs; small enough to cache for the whole catalog."""
    rules = ctrl.get("COMPLIANCE_RULES") or []
    return {
        "CONTROL_ID": ctrl.get("CONTROL_ID"),
        "CONTROL_NAME": ctrl.get("CONTROL_NAME") or "",
        "CATEGORY": ctrl.get("CATEGORY") or "",
        "SUBCATEGORY": ctrl.get("SUBCATEGORY") or "",
        "DESCRIPTION": ctrl.get("DESCRIPTION") or "",
        "STANDARDS": list(ctrl.get("STANDARDS") or []),
        "IS_CUSTOM": bool(ctrl.get("IS_CUSTOM")),
        "RULE_IDS": sorted({r.get("LOGICAL_ID") for r in rules if r.get("LOGICAL_ID")}),
        "ASSET_TYPES": sorted({a for r in rules for a in r.get("SCANNABLE_ASSETS") or []}),
    }


class Catalog:
    """Built-in controls (cached on disk) plus custom controls (always fetched fresh)."""

    def __init__(self, client: CortexClient, cache_path: Path, workers: int, refresh: bool):
        self.client = client
        self.cache_path = cache_path
        self.workers = workers
        self.builtin: list[dict] = []
        self.custom: list[dict] = []
        self.asset_enums: dict[str, str | None] = {}
        self._load(refresh)
        self.custom = [compact_control(c) for c in client.fetch_controls(
            [{"field": "is_custom", "operator": "in", "value": ["yes"]}], workers, "custom")]
        self.builtin_by_name = {c["CONTROL_NAME"]: c for c in self.builtin}
        self.custom_by_name = {c["CONTROL_NAME"]: c for c in self.custom}

    def _load(self, refresh: bool) -> None:
        if not refresh and self.cache_path.exists():
            data = json.loads(self.cache_path.read_text())
            if data.get("version") == CACHE_VERSION and data.get("tenant") == self.client.base:
                self.builtin = data["builtin"]
                self.asset_enums = data.get("asset_enums") or {}
                LOG.info("Loaded %d built-in controls from cache %s (fetched %s; use --refresh-catalog to rescan)",
                         len(self.builtin), self.cache_path, data.get("fetched_at"))
                return
        self.builtin = [compact_control(c) for c in self.client.fetch_controls(
            [{"field": "is_custom", "operator": "in", "value": ["no"]}], self.workers, "built-in")]
        self.save()

    def save(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps({
            "version": CACHE_VERSION, "tenant": self.client.base,
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "builtin": self.builtin, "asset_enums": self.asset_enums,
        }))

    def standard_names(self) -> list[str]:
        return sorted({s for c in self.builtin for s in c["STANDARDS"]})

    def controls_of(self, standard: str) -> list[dict]:
        return [c for c in self.builtin if standard in c["STANDARDS"]]

    def register_custom(self, ctrl: dict) -> None:
        self.custom.append(ctrl)
        self.custom_by_name[ctrl["CONTROL_NAME"]] = ctrl


# -------------------------------------------------------------- asset enums


def enum_candidates(display_name: str) -> list[str]:
    """Plausible enum spellings for a scannable asset display name, most likely first."""
    words = re.findall(r"[A-Za-z0-9]+", display_name.upper())
    if not words:
        return []
    base = "_".join(words)
    cands = [base]
    if len(words) > 1:
        cands.append("_".join([words[0], "CLOUD", *words[1:]]))
    cands.append("_".join(words[:-1]) if words[-1] == "INSTANCE" and len(words) > 1 else base + "_INSTANCE")
    for src, dst in (("GOOGLE", "GCP"), ("AMAZON", "AWS"), ("MICROSOFT", "AZURE"), ("ORACLE", "OCI"), ("ALIBABA", "ALIYUN")):
        if src in words:
            cands.append("_".join(dst if w == src else w for w in words))
    return list(dict.fromkeys(cands))


class AssetEnumResolver:
    """get_control reports scannable assets by display name ("EC2 Instance") while
    add_rules_to_control only accepts enum names ("EC2_INSTANCE") that the docs do not list.
    The API validates the payload before resolving the control, so probing against a
    non-existent control id tells valid from invalid names without side effects."""

    def __init__(self, client: CortexClient, known: dict[str, str | None], overrides: dict[str, str]):
        self.client = client
        self.map: dict[str, str | None] = dict(known)
        self.map.update(overrides)
        self.verified: set[str] = set(overrides)

    def _probe(self, enums: list[str]) -> bool:
        rule = {"name": "probe", "description": "", "type": "VM", "logical_id": "00000000-0000-0000-0000-000000000000",
                "severity": "low", "scannable_assets": enums, "remediation_steps": "",
                "generate_findings": True, "generate_issues": False, "generate_scan_logs": False}
        try:
            self.client._post("add_rules_to_control", {"control_id": PROBE_CONTROL_ID, "rules": [rule]}, retries=1)
        except CortexAPIError as err:
            if "scannable asset" in err.body:
                return False
            if "exist" in err.body:
                return True
            raise
        raise CortexAPIError("add_rules_to_control", 200, "probe unexpectedly succeeded")

    def resolve_all(self, display_names: Iterable[str]) -> None:
        """Aggregate every asset display name in scope and resolve the unknown ones once."""
        names = sorted(set(display_names))
        pending = [n for n in names if n not in self.map]
        LOG.info("%d scannable asset types in scope, %d already known", len(names), len(names) - len(pending))
        if pending and self._probe([enum_candidates(n)[0] for n in pending if enum_candidates(n)]):
            for n in pending:
                self.map[n] = enum_candidates(n)[0]
            pending = []
        for n in pending:
            self.map[n] = next((c for c in enum_candidates(n) if self._probe([c])), None)
            if self.map[n] is None:
                LOG.warning("Could not resolve scannable asset %r to an API enum; rules will be added without it", n)
        for n in names:
            LOG.debug("asset %-40r -> %s", n, self.map[n])

    def resolve(self, display_name: str) -> str | None:
        if display_name not in self.map:
            self.resolve_all([display_name])
        return self.map[display_name]


# ------------------------------------------------------------------- rules


def rule_severity(raw: str | None) -> str:
    """Map get_control severities such as `SEV_030_MEDIUM` to the add_rules enum."""
    text = (raw or "").lower()
    return next((s for s in RULE_SEVERITIES if s in text), "low")


def rule_payload(rule: dict, assets: AssetEnumResolver) -> tuple[dict, list[str]]:
    """Translate one COMPLIANCE_RULES entry into an add_rules_to_control rule; also return unresolved assets."""
    resolved, dropped = [], []
    for a in rule.get("SCANNABLE_ASSETS") or []:
        enum = assets.resolve(a)
        (resolved if enum else dropped).append(enum or a)
    return {
        "name": rule.get("NAME") or "",
        "description": rule.get("DESCRIPTION") or "",
        "type": rule.get("TYPE") or "",
        "logical_id": rule["LOGICAL_ID"],
        "severity": rule_severity(rule.get("SEVERITY")),
        "scannable_assets": resolved,
        "remediation_steps": rule.get("REMEDIATION_STEPS") or "",
        "generate_findings": bool(rule.get("GENERATE_FINDINGS")),
        "generate_issues": bool(rule.get("GENERATE_ISSUES")),
        "generate_scan_logs": bool(rule.get("GENERATE_SCAN_LOGS")),
    }, dropped


def mirror_rules(client: CortexClient, assets: AssetEnumResolver, source_rules: list[dict], clone_id: str,
                 existing: set[str], resync: bool, dry_run: bool) -> tuple[int, int, str]:
    """Copy `source_rules` (minus the `existing` logical ids already on the clone) onto the clone.
    Returns (added, already_present, note)."""
    notes = []
    source_ids = {r.get("LOGICAL_ID") for r in source_rules if r.get("LOGICAL_ID")}
    extra = sorted(existing - source_ids)
    if extra:
        if resync and not dry_run:
            client.delete_rules_from_control(clone_id, extra)
            notes.append(f"pruned {len(extra)} rule(s) not in source")
        else:
            notes.append(f"clone has {len(extra)} rule(s) not in source" + ("" if resync else " (see --resync-clones)"))
    if not source_rules:
        notes.append("source control has no rules")
        return 0, 0, "; ".join(notes)
    todo = [r for r in source_rules if r.get("LOGICAL_ID") and r["LOGICAL_ID"] not in existing]
    present = len(source_rules) - len(todo)
    if not todo or dry_run:
        return len(todo), present, "; ".join(notes)
    payload, dropped = [], set()
    for r in todo:
        p, d = rule_payload(r, assets)
        payload.append(p)
        dropped.update(d)
    try:
        client.add_rules_to_control(clone_id, payload)
    except CortexAPIError as err:
        if "already associated" not in err.body:
            raise
        return 0, len(source_rules), "; ".join(notes)
    if dropped:
        notes.append(f"rules added without unresolved scannable assets {sorted(dropped)}")
    return len(todo), present, "; ".join(notes)


# ------------------------------------------------------------------- matching


def normalize_name(raw: str) -> str:
    text = TRAILING_TAG_RE.sub("", str(raw).translate(SMART_QUOTES))
    while True:
        stripped = TAG_RE.sub("", IDENT_RE.sub("", text), count=1)
        if stripped == text:
            break
        text = stripped
    return re.sub(r"\s+", " ", text).strip().lower()


def setting_name(normalized: str) -> str | None:
    """The first quoted phrase, e.g. the policy setting in CIS-style names."""
    m = QUOTED_RE.search(normalized)
    return m.group(1).strip() if m else None


@dataclass
class Candidate:
    control: dict
    normalized: str
    setting: str | None

    @classmethod
    def of(cls, control: dict) -> "Candidate":
        norm = normalize_name(control.get("CONTROL_NAME", ""))
        return cls(control, norm, setting_name(norm))

    @property
    def id(self) -> str:
        return self.control["CONTROL_ID"]

    @property
    def name(self) -> str:
        return self.control.get("CONTROL_NAME", "")


@dataclass
class RowMatch:
    row_index: int
    xlsx_name: str
    normalized: str
    status: str = "unmatched"  # matched | ambiguous | fallback | unmatched
    candidate: Candidate | None = None
    ratio: float = 0.0
    score: float = 0.0
    runner_up: Candidate | None = None
    runner_up_score: float = 0.0
    tied: list[tuple[float, float, Candidate]] | None = None  # candidates within the ambiguity margin
    action: str = ""  # create | exists | skip | error
    custom_control_id: str = ""
    custom_control_name: str = ""
    rules_added: int = 0
    rules_present: int = 0
    note: str = ""


def score_pair(row_norm: str, row_setting: str | None, cand: Candidate, threshold: float) -> tuple[float, float] | None:
    """(ratio, score) or None when below threshold. The score adds a bonus when both names quote the same
    setting and a strong penalty when they quote different ones: "'Allow Basic authentication' ... 'Disabled'"
    must never match "'WDigest Authentication' ... 'Disabled'" however similar the rest of the text is."""
    matcher = SequenceMatcher(None, row_norm, cand.normalized)
    if matcher.quick_ratio() + SETTING_BONUS < threshold:
        return None
    ratio = matcher.ratio()
    score = ratio
    if row_setting and cand.setting:
        score += SETTING_BONUS if cand.setting == row_setting else -SETTING_PENALTY
    return (ratio, score) if score >= threshold else None


def match_rows(rows: list[tuple[int, str]], candidates: list[Candidate], threshold: float, ambiguity_margin: float,
               claimed: set[str] | None = None) -> list[RowMatch]:
    """Greedy one-to-one assignment: best-scoring rows claim their control first.
    Equal scores prefer the candidate with more rules; remaining ties are reported as ambiguous
    and then, where possible, broken by the categories of neighbouring spreadsheet rows."""
    ranked: list[tuple[RowMatch, list[tuple[float, float, Candidate]]]] = []
    for idx, name in rows:
        norm = normalize_name(name)
        setting = setting_name(norm)
        scored = []
        for c in candidates:
            s = score_pair(norm, setting, c, threshold)
            if s:
                scored.append((*s, c))
        scored.sort(key=lambda t: (-t[1], -len(t[2].control.get("RULE_IDS") or [])))
        ranked.append((RowMatch(idx, name, norm), scored))

    ranked.sort(key=lambda t: -(t[1][0][1] if t[1] else -1))
    taken: set[str] = set(claimed or ())
    for rm, scored in ranked:
        available = [t for t in scored if t[2].id not in taken]
        if not available:
            rm.note = "no candidate above threshold" if not scored else "all candidates already claimed by other rows"
            continue
        ratio, score, cand = available[0]
        rm.candidate, rm.ratio, rm.score = cand, ratio, score
        rm.status = "matched"
        if len(available) > 1:
            rm.runner_up, rm.runner_up_score = available[1][2], available[1][1]
            if score - available[1][1] < ambiguity_margin:
                rm.status = "ambiguous"
                rm.tied = [t for t in available if score - t[1] < ambiguity_margin]
                rm.note = f"runner-up '{rm.runner_up.name}' scored {rm.runner_up_score:.3f}"
        taken.add(cand.id)
    results = sorted((rm for rm, _ in ranked), key=lambda r: r.row_index)
    break_ties_by_neighbours(results)
    return results


def break_ties_by_neighbours(results: list[RowMatch], window: int = 3) -> None:
    """Ordered control lists cluster by section, so when identically named controls tie, the one whose
    category/subcategory matches the surrounding matched rows is almost certainly the intended one."""
    for pos, r in enumerate(results):
        if r.status != "ambiguous" or not r.tied:
            continue
        neighbour_cats = set()
        for off in range(1, window + 1):
            for j in (pos - off, pos + off):
                if 0 <= j < len(results) and results[j].status == "matched" and results[j].candidate:
                    c = results[j].candidate.control
                    neighbour_cats.add((c.get("CATEGORY"), c.get("SUBCATEGORY")))
        taken_by_others = {x.candidate.id for x in results if x is not r and x.candidate}
        fits = [t for t in r.tied
                if (t[2].control.get("CATEGORY"), t[2].control.get("SUBCATEGORY")) in neighbour_cats and t[2].id not in taken_by_others]
        if len(fits) != 1:
            continue
        ratio, score, cand = fits[0]
        losers = [t[2].name for t in r.tied if t[2].id != cand.id]
        r.candidate, r.ratio, r.score, r.status = cand, ratio, score, "matched"
        r.note = f"tie with {losers} broken by neighbouring rows' category [{cand.control.get('CATEGORY')} | {cand.control.get('SUBCATEGORY') or '-'}]"


# ----------------------------------------------------------------------- xlsx


def read_xlsx_names(path: str, sheet: str | None, column: str, skip_header: bool) -> list[tuple[int, str]]:
    """One control name per row. `column` is a 1-based index or a header title (then the header row is skipped)."""
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb[sheet] if sheet else wb.active
    rows_iter = ws.iter_rows(values_only=True)
    if column.isdigit():
        col = int(column) - 1
    else:
        header = [str(v).strip().lower() if v is not None else "" for v in next(rows_iter, ())]
        if column.strip().lower() not in header:
            raise SystemExit(f"Column '{column}' not found in header row: {header}")
        col, skip_header = header.index(column.strip().lower()), False
    rows: list[tuple[int, str]] = []
    seen: dict[str, int] = {}
    for idx, row in enumerate(rows_iter, start=2 if not column.isdigit() else 1):
        if skip_header and idx == 1:
            continue
        value = row[col] if len(row) > col else None
        if value is None or not str(value).strip():
            continue
        name = re.sub(r"\s+", " ", str(value)).strip()
        if name in seen:
            LOG.warning("Row %d duplicates row %d (%r); skipping", idx, seen[name], name)
            continue
        seen[name] = idx
        rows.append((idx, name))
    return rows


# ----------------------------------------------------------------- clone step


def clone_description(ctrl: dict, source_standard: str) -> str:
    desc = DESC_MARKER_RE.sub("", (ctrl.get("DESCRIPTION") or "").strip())
    provenance = f"Cloned from built-in control \"{ctrl.get('CONTROL_NAME')}\" ({ctrl.get('CONTROL_ID')}) of \"{source_standard}\"."
    return f"{desc}\n\n{provenance}" if desc else provenance


def collision_note(builtin: dict) -> str:
    standards = ", ".join(builtin.get("STANDARDS") or []) or "no standard"
    return f"name collides with built-in control {builtin.get('CONTROL_ID')} ({standards}); use --name-prefix/--name-suffix"


def resolve_custom_control(r: RowMatch, catalog: Catalog, name: str, source_standard: str, resync: bool, dry_run: bool) -> None:
    """Reuse the existing clone named `name`, or create it from the matched built-in control."""
    r.custom_control_name = name
    if name in catalog.custom_by_name:
        existing = catalog.custom_by_name[name]
        r.action, r.custom_control_id = "exists", existing["CONTROL_ID"]
        ctrl = r.candidate.control
        expected = (clone_description(ctrl, source_standard), ctrl.get("CATEGORY") or "Uncategorized", ctrl.get("SUBCATEGORY") or "")
        actual = (existing.get("DESCRIPTION") or "", existing.get("CATEGORY") or "", existing.get("SUBCATEGORY") or "")
        # Cortex title-cases category/subcategory of custom controls, so compare those case-insensitively.
        if (expected[0].strip(), expected[1].lower(), expected[2].lower()) != (actual[0].strip(), actual[1].lower(), actual[2].lower()):
            if resync and not dry_run:
                catalog.client.edit_control(r.custom_control_id, expected[0], expected[1], expected[2] or None)
                r.note = "metadata resynced from source"
            else:
                r.note = "clone metadata differs from source" + ("" if resync else " (see --resync-clones)")
        return
    if name in catalog.builtin_by_name:
        r.action, r.note = "skip", collision_note(catalog.builtin_by_name[name])
        return
    r.action = "create"
    if dry_run:
        return
    ctrl = r.candidate.control
    try:
        r.custom_control_id = catalog.client.add_control(
            name, clone_description(ctrl, source_standard), ctrl.get("CATEGORY") or "Uncategorized", ctrl.get("SUBCATEGORY")
        )
    except CortexAPIError as err:
        if "already exists" not in err.body:
            raise
        # The name exists but was not indexed; learn what it is and decide again.
        existing = catalog.client.lookup_control_by_name(name)
        if existing is None:
            raise
        if existing.get("IS_CUSTOM"):
            catalog.register_custom(compact_control(existing))
        else:
            catalog.builtin_by_name[name] = compact_control(existing)
        return resolve_custom_control(r, catalog, name, source_standard, resync, dry_run)
    catalog.register_custom({"CONTROL_ID": r.custom_control_id, "CONTROL_NAME": name, "IS_CUSTOM": True, "RULE_IDS": [], "STANDARDS": []})


def sync_rules(r: RowMatch, catalog: Catalog, assets: AssetEnumResolver, source_rules: list[dict], resync: bool, dry_run: bool) -> None:
    record = catalog.custom_by_name.get(r.custom_control_name) or {}
    r.rules_added, r.rules_present, note = mirror_rules(
        catalog.client, assets, source_rules, r.custom_control_id, set(record.get("RULE_IDS") or []), resync, dry_run)
    if note:
        r.note = (r.note + "; " if r.note else "") + note


# --------------------------------------------------------------------- report


def write_report(path: str, results: list[RowMatch]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["xlsx_row", "xlsx_name", "status", "ratio", "score", "source_control_id", "source_control_name",
             "source_standards", "source_category", "source_subcategory", "action", "custom_control_id",
             "custom_control_name", "rules_added", "rules_present", "runner_up_name", "runner_up_score", "note"]
        )
        for r in results:
            c = r.candidate.control if r.candidate else {}
            w.writerow([
                r.row_index, r.xlsx_name, r.status, f"{r.ratio:.3f}", f"{r.score:.3f}",
                c.get("CONTROL_ID", ""), c.get("CONTROL_NAME", ""), "; ".join(c.get("STANDARDS") or []),
                c.get("CATEGORY", ""), c.get("SUBCATEGORY", ""),
                r.action, r.custom_control_id, r.custom_control_name, r.rules_added, r.rules_present,
                r.runner_up.name if r.runner_up else "", f"{r.runner_up_score:.3f}" if r.runner_up else "", r.note,
            ])


# ----------------------------------------------------------------------- main


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=value, optional quotes, # comments). Existing environment wins."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    load_dotenv(Path(os.getenv("CORTEX_ENV_FILE", ".env")))
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    io = p.add_argument_group("input")
    io.add_argument("--xlsx", required=True, help="Spreadsheet with one control name per row")
    io.add_argument("--sheet", help="Worksheet name (default: active sheet)")
    io.add_argument("--column", default="1", help="1-based column index, or a header title (header row is then skipped)")
    io.add_argument("--skip-header", action="store_true", help="Skip the first row when --column is an index")
    std = p.add_argument_group("standards")
    std.add_argument("--source-standard", required=True, help="Built-in standard whose controls are matched and cloned")
    std.add_argument("--target-standard", required=True, help="Custom standard that receives the clones")
    std.add_argument("--create-target", action="store_true", help="Create the target standard if it does not exist")
    std.add_argument("--name-prefix", default="", help="Prepended to every spreadsheet name to form the custom control name "
                     "(control names are unique tenant-wide, so bare names often collide with other built-in standards)")
    std.add_argument("--name-suffix", default="", help="Appended to every spreadsheet name to form the custom control name")
    std.add_argument("--no-rules", action="store_true", help="Do not mirror the built-in control's compliance rules onto the clones")
    std.add_argument("--resync-clones", action="store_true",
                     help="Make existing clones conform to their matched source: refresh description/category and remove "
                          "rules the source does not have (otherwise differences are only reported)")
    std.add_argument("--asset-map", help="JSON file {display name: ENUM_NAME} overriding discovered scannable asset enums")
    mt = p.add_argument_group("matching")
    mt.add_argument("--threshold", type=float, default=0.85, help="Minimum similarity ratio (0-1) to accept a match")
    mt.add_argument("--ambiguity-margin", type=float, default=0.02, help="Flag a match as ambiguous when the runner-up is within this score margin")
    mt.add_argument("--skip-ambiguous", action="store_true", help="Do not clone/attach ambiguous matches")
    mt.add_argument("--fallback-threshold", type=float, default=0.95,
                    help="Rows unmatched within the source standard are matched against every other built-in control at this stricter ratio")
    mt.add_argument("--no-fallback", action="store_true", help="Disable the catalog-wide fallback match")
    mt.add_argument("--skip-fallback", action="store_true", help="Report fallback matches (outside the source standard) but do not clone/attach them")
    api = p.add_argument_group("tenant")
    api.add_argument("--fqdn", default=os.getenv("CORTEX_FQDN"), help="Tenant API host, e.g. api-xxx.xdr.us.paloaltonetworks.com (env CORTEX_FQDN)")
    api.add_argument("--api-key-id", default=os.getenv("CORTEX_API_KEY_ID"), help="x-xdr-auth-id (env CORTEX_API_KEY_ID)")
    api.add_argument("--api-key", default=os.getenv("CORTEX_API_KEY"), help="API key for the Authorization header (env CORTEX_API_KEY)")
    api.add_argument("--catalog-cache", help="Path of the built-in catalog cache (default: .cortex_cache/<fqdn>.json)")
    api.add_argument("--refresh-catalog", action="store_true", help="Rescan the built-in catalog instead of using the cache")
    api.add_argument("--workers", type=int, default=4, help="Parallel page requests when scanning the catalog")
    api.add_argument("--attach-batch-size", type=int, default=50, help="Controls added per edit_standard call")
    run = p.add_argument_group("run")
    run.add_argument("--limit", type=int, help="Only process the first N spreadsheet rows (testing)")
    run.add_argument("--report", default="sync_report.csv", help="CSV report path")
    run.add_argument("--dry-run", action="store_true", help="Match and report only; create/modify nothing")
    run.add_argument("--list-standards", action="store_true", help="Print the built-in standards found in the catalog and exit")
    run.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    for opt in ("fqdn", "api_key_id", "api_key"):
        if not getattr(args, opt):
            p.error(f"--{opt.replace('_', '-')} is required (or set CORTEX_{opt.upper()})")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    mode = "DRY RUN" if args.dry_run else "LIVE"
    LOG.info("[%s] reading %s", mode, args.xlsx)
    rows = read_xlsx_names(args.xlsx, args.sheet, args.column, args.skip_header)
    if args.limit:
        rows = rows[: args.limit]
    LOG.info("%d control names loaded from spreadsheet", len(rows))
    if not rows:
        return 1

    client = CortexClient(args.fqdn, args.api_key_id, args.api_key)
    host = re.sub(r"^https?://", "", args.fqdn).strip("/").replace("/", "_")
    catalog = Catalog(client, Path(args.catalog_cache or f".cortex_cache/{host}.json"), args.workers, args.refresh_catalog)
    if args.list_standards:
        for name in catalog.standard_names():
            print(f"{len(catalog.controls_of(name)):5d}  {name}")
        return 0

    source_controls = catalog.controls_of(args.source_standard)
    if not source_controls:
        close = [n for n in catalog.standard_names() if args.source_standard.lower() in n.lower()]
        raise SystemExit(f"No built-in controls belong to '{args.source_standard}'."
                         + (f" Did you mean: {close}" if close else " Use --list-standards to see what exists."))
    LOG.info("%d built-in controls in source standard '%s'", len(source_controls), args.source_standard)

    target = client.find_standard(args.target_standard)
    if target is None:
        if not args.create_target:
            raise SystemExit(f"Target standard '{args.target_standard}' not found (use --create-target to create it).")
        LOG.info("%s target standard '%s'", "Would create" if args.dry_run else "Creating", args.target_standard)
        if not args.dry_run:
            client.add_standard(args.target_standard, f"Built from {Path(args.xlsx).name} against '{args.source_standard}' by xlsx_to_cortex_controls.")
            target = client.find_standard(args.target_standard)
    elif not target.get("is_custom"):
        raise SystemExit(f"'{args.target_standard}' is a built-in standard; only custom standards can be edited.")
    existing_ids: list[str] = []
    if target:
        target = client.get_standard(target["id"])
        existing_ids = list(target.get("controls_ids") or [])
        LOG.info("Target standard '%s' (%s) currently has %d controls", target["name"], target["id"], len(existing_ids))

    candidates = [Candidate.of(c) for c in source_controls]
    results = match_rows(rows, candidates, args.threshold, args.ambiguity_margin)
    unmatched = [r for r in results if r.status == "unmatched"]
    if unmatched and not args.no_fallback:
        LOG.info("Fallback: matching %d unmatched rows against the whole built-in catalog (ratio >= %.2f)", len(unmatched), args.fallback_threshold)
        source_ids = {c["CONTROL_ID"] for c in source_controls}
        others = [Candidate.of(c) for c in catalog.builtin if c["CONTROL_ID"] not in source_ids]
        fallback = match_rows([(r.row_index, r.xlsx_name) for r in unmatched], others, args.fallback_threshold, args.ambiguity_margin)
        by_row = {f.row_index: f for f in fallback}
        for i, r in enumerate(results):
            f = by_row.get(r.row_index)
            if f and f.status != "unmatched":
                origin = "; ".join(f.candidate.control["STANDARDS"]) or "no standard"
                f.note = (f.note + "; " if f.note else "") + f"matched outside source standard: {origin}"
                if f.status == "matched":
                    f.status = "fallback"
                results[i] = f

    assets = None
    source_rules: dict[str, list[dict]] = {}
    if not args.no_rules:
        overrides = json.loads(Path(args.asset_map).read_text()) if args.asset_map else {}
        assets = AssetEnumResolver(client, catalog.asset_enums, overrides)
        in_scope = {a for r in results if r.candidate for a in r.candidate.control.get("ASSET_TYPES") or []}
        assets.resolve_all(in_scope)
        catalog.asset_enums = {k: v for k, v in assets.map.items() if v}
        catalog.save()
        matched_ids = [r.candidate.id for r in results if r.candidate]
        LOG.info("Fetching full records (rules) of %d source controls ...", len(set(matched_ids)))
        source_rules = {cid: c.get("COMPLIANCE_RULES") or [] for cid, c in client.get_controls_by_id(matched_ids, args.workers).items()}

    to_attach: list[str] = []
    created = reused = skipped = rules_added = 0
    for r in results:
        if r.status == "unmatched" or (r.status == "ambiguous" and args.skip_ambiguous) or (r.status == "fallback" and args.skip_fallback):
            r.action = "skip"
            skipped += 1
            LOG.warning("SKIP   row %-4d %s  [%s]%s", r.row_index, r.xlsx_name, r.status, f" {r.note}" if r.note else "")
            continue
        ctrl = r.candidate.control
        match_note, r.note = r.note, ""
        try:
            resolve_custom_control(r, catalog, f"{args.name_prefix}{r.xlsx_name}{args.name_suffix}", args.source_standard,
                                   args.resync_clones, args.dry_run)
            if r.action in ("create", "exists") and assets is not None:
                sync_rules(r, catalog, assets, source_rules.get(r.candidate.id, []), args.resync_clones, args.dry_run)
        except CortexAPIError as err:
            LOG.error("row %d (%s) failed: %s", r.row_index, r.xlsx_name, err)
            if r.action in ("create", "exists") and r.custom_control_id:
                r.note = f"rules not synced: {err.body[:160]}"  # control exists; rules are retried on re-run
            else:
                r.action, r.note = "error", str(err)
        if match_note:
            prefix = f"{r.status.upper()}: " if r.status in ("ambiguous", "fallback") else ""
            r.note = f"{prefix}{match_note}" + (f"; {r.note}" if r.note else "")
        detail = f"  [{r.note}]" if r.note else ""
        if r.action in ("skip", "error"):
            skipped += 1
            LOG.warning("SKIP   row %-4d %s%s", r.row_index, r.xlsx_name, detail)
            continue
        rules_added += r.rules_added
        rules_info = f" rules +{r.rules_added}/={r.rules_present}" if assets is not None else ""
        if r.action == "exists":
            reused += 1
            LOG.info("EXISTS row %-4d %s -> custom %s%s%s", r.row_index, r.custom_control_name, r.custom_control_id, rules_info, detail)
        else:
            created += 1
            LOG.info("CLONE  row %-4d %s  <=  %s [%s | %s] (ratio %.3f)%s%s", r.row_index, r.custom_control_name,
                     ctrl.get("CONTROL_NAME"), ctrl.get("CATEGORY"), ctrl.get("SUBCATEGORY") or "-", r.ratio, rules_info, detail)
        if r.custom_control_id or args.dry_run:
            to_attach.append(r.custom_control_id or f"<new:{r.row_index}>")

    new_ids = [cid for cid in to_attach if cid not in existing_ids]
    not_attached: list[str] = []
    if new_ids:
        LOG.info("%s %d controls to standard '%s' (%d already attached)", "Would attach" if args.dry_run else "Attaching",
                 len(new_ids), args.target_standard, len(to_attach) - len(new_ids))
        if not args.dry_run and target:
            not_attached = client.attach_controls(target["id"], existing_ids, new_ids, args.attach_batch_size)
            if not_attached:
                LOG.error("%d controls could not be attached (clones exist; re-run to retry)", len(not_attached))
                for r in results:
                    if r.custom_control_id in not_attached:
                        r.note = (r.note + "; " if r.note else "") + "NOT ATTACHED"
    else:
        LOG.info("All matched controls are already attached; nothing to update")

    write_report(args.report, results)
    counts = {s: sum(1 for r in results if r.status == s) for s in ("matched", "ambiguous", "fallback", "unmatched")}
    print(f"\n[{mode}] rows={len(results)} matched={counts['matched']} ambiguous={counts['ambiguous']} "
          f"fallback={counts['fallback']} unmatched={counts['unmatched']} "
          f"clones_{'planned' if args.dry_run else 'created'}={created} reused={reused} "
          f"skipped={skipped} rules_{'to_add' if args.dry_run else 'added'}={rules_added} "
          f"attached={len(new_ids) - len(not_attached)}  report={args.report}")
    for r in results:
        if r.status != "matched" or r.action in ("skip", "error") or r.note:
            label = r.status.upper() if r.status != "matched" else r.action.upper()
            print(f"  - {label:9} row {r.row_index}: {r.xlsx_name}" + (f"  ({r.note})" if r.note else ""))
    return 1 if not_attached else 0


if __name__ == "__main__":
    sys.exit(main())
