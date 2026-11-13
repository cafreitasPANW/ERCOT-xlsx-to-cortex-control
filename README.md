# xlsx → Cortex Cloud custom compliance standard

Turn a spreadsheet of control names (a customer's customised benchmark, an
auditor's checklist, …) into a Cortex Cloud custom compliance standard whose
controls are clones of the matching built-in controls, **rules included**.

Nothing is tied to one standard: point it at any xlsx, any built-in *source*
standard and any custom *target* standard.

For every spreadsheet row the script:

1. **Matches** the name to a control of the source standard, ignoring leading
   identifiers and level tags on both sides (`1.1.1`, `18.10.57.2.2`, `A.5.1`,
   `AC-2`, `CC6.1`, `(L1)`, `(L2)`, trailing `(Automated)`…) and tolerating small
   textual differences such as customised thresholds (`'10 or more password(s)'`
   vs `'24 or more password(s)'`). The quoted setting name (`'Enforce password
   history'`) is treated as the control's identity: same setting = bonus,
   different setting = strong penalty. Identically named controls (e.g. CIS
   *Computer* vs *User* administrative templates) are disambiguated by the
   category of the neighbouring spreadsheet rows; anything still ambiguous is
   flagged.
2. **Clones** the matched built-in control as a custom control named
   `<prefix><xlsx name><suffix>`, copying category, sub-category and description
   and recording the source control id in the description.
3. **Mirrors the rules**: fetches the built-in control's full record
   (`get_control`) and adds its `COMPLIANCE_RULES` to the clone
   (`add_rules_to_control`) — name, type, logical id, severity, scannable
   assets, remediation steps and the generate-findings/issues/scan-logs flags.
4. **Attaches** all clones to the target standard, preserving whatever is
   already attached.

Every run is idempotent: existing clones are reused, rules already present
(matched by `logical_id`) are not re-added, attached controls are left alone.
A CSV report (`sync_report.csv`) documents exactly what each row maps to.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env     # then fill in CORTEX_FQDN, CORTEX_API_KEY_ID, CORTEX_API_KEY
```

The script reads `.env` from the working directory automatically (no extra
dependency); shell variables take precedence, and `CORTEX_ENV_FILE=other.env`
points it at a different file. `.env` is gitignored — never commit real keys.
The same three values can also be passed as `--fqdn / --api-key-id / --api-key`.

## Usage

```bash
# which built-in standards exist in the tenant (and how many controls each has)
.venv/bin/python xlsx_to_cortex_controls.py --xlsx any.xlsx --source-standard x --target-standard y --list-standards

# see what would happen; nothing is created or modified
.venv/bin/python xlsx_to_cortex_controls.py \
  --xlsx win2022_tenable.xlsx \
  --source-standard "CIS Microsoft Windows Server 2022 Benchmark v3.0.0" \
  --target-standard "ERCOT custom standard for 2022 windows" \
  --name-prefix "ERCOT - " \
  --dry-run

# do it (add --create-target if the custom standard does not exist yet)
.venv/bin/python xlsx_to_cortex_controls.py --xlsx ... --source-standard "..." --target-standard "..." --name-prefix "..."
```

All options (`--help`):

| group | option | purpose |
|---|---|---|
| input | `--xlsx`, `--sheet`, `--column`, `--skip-header` | `--column` is a 1-based index **or a header title** (header row then skipped automatically) |
| standards | `--source-standard`, `--target-standard`, `--create-target` | names as shown in Cortex; target must be custom |
| | `--name-prefix` / `--name-suffix` | control names are unique tenant-wide, and CIS-style names usually already exist as built-ins of sibling standards; a prefix avoids the collisions (reported otherwise) |
| | `--no-rules` | clone and attach without copying rules |
| | `--resync-clones` | make existing clones conform to their matched source (refresh description/category, remove rules the source lacks); without it differences are only reported |
| | `--asset-map file.json` | override discovered scannable-asset enum names |
| matching | `--threshold 0.85` | min. similarity to accept a match within the source standard |
| | `--ambiguity-margin 0.02`, `--skip-ambiguous` | near-ties are flagged `AMBIGUOUS`; optionally skip them |
| | `--fallback-threshold 0.95`, `--no-fallback`, `--skip-fallback` | rows unmatched in the source standard are tried against the whole built-in catalog at a stricter ratio; such matches are flagged `FALLBACK` |
| tenant | `--catalog-cache`, `--refresh-catalog`, `--workers 4` | built-in catalog cache (see below) |
| | `--attach-batch-size 50` | controls per `edit_standard` call |
| run | `--dry-run`, `--limit N`, `--report FILE`, `--list-standards`, `-v` | |

## How the generic parts work

**Catalog scan + cache.** `get_controls` cannot filter by standard, so the
script pages through every built-in control once (≈22k controls, 100 per
page, in parallel) and caches a compact copy in `.cortex_cache/<fqdn>.json`.
Source candidates are the cached controls whose `STANDARDS` include the source
standard; the same cache provides the collision check for control names and
the fallback pool. Custom controls are always fetched fresh (they change as the
script runs). Use `--refresh-catalog` after Cortex content updates.

**Scannable asset enums.** `get_control` reports scannable assets by display
name (`"EC2 Instance"`) while `add_rules_to_control` only accepts enum names
(`EC2_INSTANCE`) that the docs do not list. At the start of each run the script
aggregates every asset display name used by the matched source controls and
resolves each one by probing `add_rules_to_control` with candidate spellings
against a non-existent control id — the API validates the payload before it
looks up the control, so the probe is side-effect free (`400 "not a valid rule
scannable asset"` = wrong spelling, `500 "control doesn't exist"` = right one).
Learned enums are stored in the cache; `--asset-map` overrides them. An asset
that cannot be resolved is dropped from the rule and the row is annotated.

**Clone fidelity.** For existing clones the script compares description,
category, sub-category and rule set with the matched source. Differences are
reported (`clone metadata differs from source`, `clone has N rule(s) not in
source`) and fixed when `--resync-clones` is given.

## Report columns

`xlsx_row, xlsx_name, status (matched|ambiguous|fallback|unmatched), ratio,
score, source_control_id, source_control_name, source_standards,
source_category, source_subcategory, action (create|exists|skip|error),
custom_control_id, custom_control_name, rules_added, rules_present,
runner_up_name, runner_up_score, note`

Every row that is not a plain `matched` or carries a note is also printed at
the end of the run — read those.

## API behaviour worth knowing

* Only **custom** controls can be attached to a custom standard through the API
  (the UI allows built-ins); that is why controls are cloned.
* `get_controls` pages are capped at 100 and the default sort is unstable; the
  script sorts by `id` and de-duplicates.
* `edit_standard` with hundreds of controls takes >100 s server-side and the
  gateway may return a timeout/500 even though the change was applied; the
  script attaches in batches and confirms each via `get_standard`.
* Re-adding an already-linked rule returns HTTP 500 `already associated`;
  treated as success. Name collisions on `add_control` also come back as 500.
* Cortex title-cases category/sub-category of custom controls
  (`MS Security Guide` → `Ms Security Guide`); comparisons ignore case.

Timing on a ~22k-control tenant: first catalog scan ≈ 7 min (then cached);
a dry run or re-run of ~270 rows ≈ 3 min; a first live run ≈ 15–25 min.

## Results for `win2022_tenable.xlsx` (CIS Windows Server 2022 v3.0.0)

264 of 267 rows match cleanly. The remaining three are flagged `AMBIGUOUS`
because Cortex's 2022 standard has a single control where CIS lists a WinRM
*Client* and a WinRM *Service* variant (`Allow Basic authentication`,
`Allow unencrypted traffic`) and lacks `Do not allow passwords to be saved`;
the fallback finds exact-name matches in the 2016/Win11 standards. Decide per
row: run without `--skip-ambiguous` to clone them from those standards, or
leave them out.
