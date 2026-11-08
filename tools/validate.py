"""Validate every rule in rules/: the gate a rule passes before it is merged.

    python tools/validate.py            # all rules
    python tools/validate.py FILE...    # some (a file outside rules/ is checked as new)
    python tools/validate.py --fix FILE...   # normalise first, then check
    python tools/validate.py --sigmahq DIR FILE...   # also against a SigmaHQ clone

--fix does the mechanical part so a rule's author (person or model) does not:
strips markdown fences, gives a missing or invalid `id` a new UUIDv4, fills a
missing `date` (today) and `status` (experimental), puts the fields in the
order below, and renames the file to YYYY-MM-DD_<product>_<category>_<slug>.yml
from its date, logsource and title. It never touches the detection or the tests.

Checks, per rule: it parses as Sigma (pySigma) with no validator issue; the
required fields; `id` is a UUIDv4 and unique across the repository; the file name
and folder match the logsource; the logsource is one Artifact Engine evaluates;
`status` and `level` are ones triage reads; `falsepositives` names real cases;
no IP address or hash inside `detection` (those are IOCs, not behaviour);
only fields the evaluated source has (web: cs-*/sc-status; Linux process: the
history/ps fields; Linux syslog: keywords only); a Sysmon-only category says so,
unless it selects only fields the engine also reads from disk (DISK_FIELDS).

Tests, evaluated with pySigma's SQLite backend:
- at least 2 `# test-match:` and 1 `# test-nomatch:` line, and each behaves;
- every test-nomatch is a near miss: it shares a word with some test-match (the
  same binary, flag or path), so it shows the legitimate use of the same tool;
- the rule matches nothing in the benign corpus for its logsource
  (tests/benign/<folder>.txt: one ordinary event per line, same syntax).

Overlap: a rule whose `field=value` pairs are mostly another rule's (same
folder) is a duplicate (the same name as parent in one and child in the other
is not); improve that rule instead, keeping its `id`. With a SigmaHQ copy, each
value weighs by how rare it is there: `powershell.exe` (in hundreds of rules)
counts almost nothing, `deletejournal` counts fully.

SigmaHQ (`--sigmahq DIR` or the SIGMAHQ_DIR variable: a SigmaHQ clone): every
SigmaHQ rule of the same logsource runs over the rule's test-match events, with
a field the event lacks as empty text (so SigmaHQ's own filters do not hide the
hit). Each test-match a SigmaHQ rule matches is printed as `warn`, naming it;
when SigmaHQ matches every test-match the rule is likely a duplicate. A warn
does not fail the run; keep the rule only if it adds something the SigmaHQ one
does not, and say what in a `# beyond-sigmahq:` comment. Without a copy the
check is skipped (CI has none).
Exit 1 on any failure.
"""
from __future__ import annotations

import math
import os
import re
import sqlite3
import sys
import uuid
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqlite as sqlite_mod
from sigma.collection import SigmaCollection
from sigma.validators.core import validators

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
BENIGN = ROOT / "tests" / "benign"
NAME = re.compile(r"^\d{4}-\d{2}-\d{2}_[a-z0-9]+_[a-z0-9_]+_[a-z0-9-]+\.yml$")
REQUIRED = ("title", "id", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level")
LEVELS = {"critical", "high", "medium"}
STATUSES = {"experimental", "test", "stable"}
VAGUE_FP = {"", "unknown", "none", "n/a", "na", "unlikely", "-"}
# Folder for a logsource: windows/<category> or windows/builtin/<service>,
# linux/<category or service>, web/.
SUPPORTED_WINDOWS_SERVICES = {
    "security", "system", "application", "powershell", "powershell-classic",
    "taskscheduler", "wmi", "windefend", "bits-client", "smbclient-security",
    "smbclient-connectivity", "terminalservices-localsessionmanager",
    "terminalservices-remoteconnectionmanager", "sysmon"}
TEST = re.compile(r"^#\s*test-(match|nomatch):\s*(.+)$", re.M)
FIELD = re.compile(r"([A-Za-z_][\w.]*)\s*(?:NOT\s+)?(?:LIKE\b|=|IN\b|GLOB\b|REGEXP\b)", re.I)
FROM = re.compile(r"(\bFROM\s+)(<TABLE_NAME>|\w+)", re.I)
PAIR = re.compile(r'([\w-]+)=(?:"([^"]*)"|(\S+))')
WORD = re.compile(r"[a-z0-9_][a-z0-9_.:-]{2,}")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HASH = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])", re.I)
# Words every path shares: a near miss must share something about the tool itself.
COMMON = {"windows", "system32", "syswow64", "program", "files", "x86", "programdata",
          "users", "appdata", "local", "roaming", "temp", "downloads", "desktop",
          "documents", "public", "usr", "bin", "sbin", "opt", "var", "tmp", "home"}
OVERLAP = 0.6   # share of the smaller rule's detection values found in the other
# SigmaHQ folders whose rules alert (threat-hunting, compliance, placeholder do not).
SIGMAHQ_SETS = ("rules", "rules-emerging-threats", "rules-dfir")
ROW = "_aeng_row"
BEYOND = re.compile(r"^#\s*beyond-sigmahq:\s*(.+)$", re.M)
DUPLICATE = "likely a duplicate"
ORDER = ("title", "id", "status", "description", "references", "author", "date",
         "modified", "tags", "logsource", "detection", "falsepositives", "level")
WEB_FIELDS = {"cs-method", "cs-uri", "cs-uri-stem", "cs-uri-query", "cs-user-agent",
              "cs-referer", "cs-host", "sc-status", "c-ip"}
LINUX_PROC_FIELDS = {"Image", "CommandLine", "User", "ParentImage", "ParentCommandLine"}
# Windows categories only Sysmon produces: they fire on the rare host that ran it.
SYSMON_ONLY = {"file_event", "file_delete", "file_access", "file_change", "file_rename",
               "registry_event", "registry_add", "registry_set", "registry_delete",
               "registry_rename", "network_connection", "image_load", "dns_query",
               "process_access", "create_remote_thread", "pipe_created", "driver_load",
               "raw_access_thread", "create_stream_hash", "process_tampering",
               "wmi_event", "clipboard_capture"}
# ...except these, which the engine also builds from the disk (alert_win_sigma):
# MFT/USN -> file_event/file_delete, registry hives -> registry_*, netstat ->
# network_connection. A rule that selects only these fields fires without Sysmon.
_REG = {"TargetObject", "Details", "EventType"}
DISK_FIELDS = {"file_event": {"TargetFilename"}, "file_delete": {"TargetFilename"},
               "registry_set": _REG, "registry_event": _REG, "registry_add": _REG,
               "network_connection": {"Image", "User", "Protocol", "SourceIp", "SourcePort",
                                      "DestinationIp", "DestinationPort", "Initiated"}}


def expected_folder(ls: dict) -> tuple[Path | None, str]:
    product = (ls.get("product") or "").lower()
    cat = (ls.get("category") or "").lower()
    svc = (ls.get("service") or "").lower()
    if cat == "webserver":
        return Path("web"), ""
    if product == "windows":
        if cat:
            return Path("windows") / cat, ""
        if svc in SUPPORTED_WINDOWS_SERVICES:
            return Path("windows") / "builtin" / svc, ""
        return None, f"windows service `{svc}` is not a channel the acquisitions collect"
    if product == "linux":
        return Path("linux") / (cat or svc or "syslog"), ""
    return None, f"logsource {ls} is not evaluated by Artifact Engine"


def event_of(spec: str) -> dict[str, str]:
    """`Field="value with spaces" Other=value` -> {Field: ..., Other: ...}."""
    return {k: (q if q or not u else u) for k, q, u in PAIR.findall(spec)}


def to_sql(rule_yaml: str) -> str:
    return sqlite_mod.sqliteBackend().convert(SigmaCollection.from_yaml(rule_yaml))[0]


def run_sql(q: str, events: list[dict[str, str]], fill: str | None = None) -> list[bool]:
    """Whether the query matches each event (one SQLite row per event). `fill` is
    the value of a field the event lacks (None = SQL NULL)."""
    fields = set(re.findall(r"`([^`]+)`", q)) | set(FIELD.findall(q))
    for e in events:
        fields |= set(e)
    fields.discard(ROW)
    cols = sorted(fields)
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE t (" + ", ".join(f'"{c}" TEXT' for c in [ROW, *cols]) + ")")
    con.executemany(f"INSERT INTO t VALUES ({','.join('?' * (len(cols) + 1))})",
                    [[i, *(e.get(c, fill) for c in cols)] for i, e in enumerate(events)])
    cur = con.execute(FROM.sub(r"\1t", q, count=1))
    at = [d[0] for d in cur.description].index(ROW)
    hit = {int(r[at]) for r in cur.fetchall()}
    return [i in hit for i in range(len(events))]


def evaluate(rule_yaml: str, events: list[dict[str, str]]) -> list[bool]:
    """Whether the rule matches each event (one SQLite row per event)."""
    return run_sql(to_sql(rule_yaml), events)


def logsource_key(ls: dict) -> tuple[str, ...]:
    return tuple(str(ls.get(k) or "").lower() for k in ("product", "category", "service"))


class SigmaHQ:
    """The SigmaHQ rules that alert, by logsource; each converted once, when needed."""

    def __init__(self, root: Path):
        self.root = root
        self.by_source: dict[tuple, list[tuple[Path, str, str]]] = {}
        self.df: dict[str, int] = {}   # value -> how many SigmaHQ rules use it
        self._sql: dict[Path, str | None] = {}
        self.rules = 0
        for name in SIGMAHQ_SETS:
            for p in sorted((root / name).rglob("*.yml")):
                try:
                    text = p.read_text(encoding="utf-8")
                    d = yaml.safe_load(text)
                except (yaml.YAMLError, UnicodeDecodeError):
                    continue
                if not isinstance(d, dict) or str(d.get("status", "")) == "deprecated":
                    continue
                self.rules += 1
                self.by_source.setdefault(logsource_key(d.get("logsource") or {}), []).append(
                    (p, str(d.get("title", "")), text))
                for v in {x.split("=", 1)[1] for x in pairs(d.get("detection") or {})}:
                    self.df[v] = self.df.get(v, 0) + 1

    def weight(self, pair: str) -> float:
        """How much a `field=value` says: 1.0 when no SigmaHQ rule uses the value,
        near 0 when most do."""
        n = self.df.get(pair.split("=", 1)[1], 0)
        return math.log((self.rules + 1) / (n + 1)) / math.log(self.rules + 1)

    def matches(self, rule: dict, events: list[dict[str, str]]) -> list[list[tuple[str, str]]]:
        """Per event, (path, title) of each SigmaHQ rule of the same logsource that
        matches it; a field the event lacks is empty text."""
        out: list[list[tuple[str, str]]] = [[] for _ in events]
        rid = str(rule.get("id", ""))
        for p, title, text in self.by_source.get(logsource_key(rule.get("logsource") or {}), []):
            if rid and rid in text:
                continue
            if p not in self._sql:
                try:
                    self._sql[p] = to_sql(text)
                except Exception:  # noqa: BLE001 - a rule the backend cannot convert
                    self._sql[p] = None
            q = self._sql[p]
            if q is None:
                continue
            try:
                hits = run_sql(q, events, fill="")
            except sqlite3.Error:  # e.g. REGEXP, which plain SQLite lacks
                continue
            for i, h in enumerate(hits):
                if h:
                    out[i].append((p.relative_to(self.root).as_posix(), title))
        return out


def sigmahq_warnings(text: str, rule: dict, hq: SigmaHQ | None) -> list[str]:
    """One line per test-match a SigmaHQ rule already matches, then the verdict
    when SigmaHQ matches every one of them."""
    if hq is None:
        return []
    specs = [spec for kind, spec in TEST.findall(text) if kind == "match"]
    if not specs:
        return []
    found = hq.matches(rule, [event_of(s) for s in specs])
    out = []
    for n, hits in enumerate(found, 1):
        if hits:
            more = f" (+{len(hits) - 2} more)" if len(hits) > 2 else ""
            names = "; ".join(f"{title} [{path}]" for path, title in hits[:2])
            out.append(f"test-match {n} already detected by SigmaHQ: {names}{more}")
    if all(found):
        reason = BEYOND.search(text)
        out.append(f"SigmaHQ detects all {len(found)} test-match; kept because: "
                   f"{reason.group(1).strip()}" if reason else
                   f"{DUPLICATE}: SigmaHQ detects all {len(found)} test-match (keep it "
                   f"only with a `# beyond-sigmahq:` line saying what it adds)")
    return out


def words(event: dict[str, str]) -> set[str]:
    return {w for v in event.values() for w in WORD.findall(v.lower())} - COMMON


def leaves(node) -> list[str]:
    """Every value in a detection, as text (keys and `condition` left out)."""
    if isinstance(node, dict):
        return [x for k, v in node.items() if k != "condition" for x in leaves(v)]
    if isinstance(node, list):
        return [x for v in node for x in leaves(v)]
    return [] if node is None else [str(node)]


def pairs(node, field: str = "") -> set[str]:
    """`field=value` for every value in a detection, lower-cased, for the overlap
    check: the same name as a parent and as a child is not the same detection."""
    if isinstance(node, dict):
        return {x for k, v in node.items() if k != "condition"
                for x in pairs(v, str(k).split("|")[0] if isinstance(v, (str, int, list))
                               and not isinstance(v, dict) else field)}
    if isinstance(node, list):
        return {x for v in node for x in pairs(v, field)}
    return set() if node is None else {f"{field}={node}".lower()}


def overlap_share(a: set[str], b: set[str], hq: SigmaHQ | None = None) -> float:
    """Share of the smaller set's weight the other also has: weight 1 per value
    without SigmaHQ, by rarity in SigmaHQ with it."""
    w = hq.weight if hq is not None else (lambda _p: 1.0)
    smaller = min(sum(w(x) for x in a), sum(w(x) for x in b))
    return sum(w(x) for x in a & b) / smaller if smaller > 0 else 0.0


def fields_of(detection: dict) -> set[str]:
    """Field names a detection selects on (modifiers dropped); keywords add none."""
    out: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                out.add(str(k).split("|")[0])
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for name, sel in (detection or {}).items():
        if name != "condition":
            walk(sel)
    return out


def source_problems(rule: dict) -> list[str]:
    ls = rule.get("logsource") or {}
    product = (ls.get("product") or "").lower()
    cat = (ls.get("category") or "").lower()
    svc = (ls.get("service") or "").lower()
    used = fields_of(rule.get("detection") or {})
    bad: list[str] = []
    if cat == "webserver" and used - WEB_FIELDS:
        bad.append(f"field(s) {sorted(used - WEB_FIELDS)} not in a web access log "
                   f"(only {sorted(WEB_FIELDS)})")
    if product == "linux" and cat == "process_creation" and used - LINUX_PROC_FIELDS:
        bad.append(f"field(s) {sorted(used - LINUX_PROC_FIELDS)} not in shell history/ps "
                   f"(only {sorted(LINUX_PROC_FIELDS)})")
    # The engine's routing (sigma_engine._table_for): auditd service or these
    # categories go to the auditd table; every other Linux rule runs as keywords.
    keyword_only = product == "linux" and svc != "auditd" and cat not in {
        "process_creation", "network_connection", "file_event", "file_create",
        "file_delete", "file_change", "file_rename"}
    if keyword_only and used:
        bad.append("Linux syslog rules are matched as keywords per line: use `keywords:` "
                   f"lists, not field selections ({sorted(used)})")
    if product == "windows" and cat in SYSMON_ONLY and not used <= DISK_FIELDS.get(cat, set()):
        text = f"{rule.get('description', '')} {rule.get('falsepositives', '')}".lower()
        if "sysmon" not in text:
            extra = sorted(used - DISK_FIELDS[cat]) if cat in DISK_FIELDS else []
            why = (f"field(s) {extra} exist only in Sysmon events (from disk: "
                   f"{sorted(DISK_FIELDS[cat])})" if extra else f"`{cat}` exists only where Sysmon ran")
            bad.append(f"{why}: say so in the description")
    return bad


def benign_events(folder: Path) -> list[tuple[str, dict[str, str]]]:
    f = BENIGN / (folder.as_posix() + ".txt")
    if not f.is_file():
        return []
    lines = [ln.strip() for ln in f.read_text(encoding="utf-8").splitlines()]
    return [(ln, event_of(ln)) for ln in lines if ln and not ln.startswith("#")]


def check(path: Path, seen: dict[str, Path], corpus: dict[Path, dict],
          hq: SigmaHQ | None = None) -> list[str]:
    text = path.read_text(encoding="utf-8")
    bad: list[str] = []
    if not NAME.match(path.name):
        bad.append("file name is not YYYY-MM-DD_product_category_slug.yml")
    docs = [d for d in yaml.safe_load_all(text) if d]
    if len(docs) != 1:
        return bad + [f"{len(docs)} YAML documents: one rule per file"]
    rule = docs[0]
    bad += [f"missing `{k}`" for k in REQUIRED if k not in rule]
    rid = str(rule.get("id", ""))
    try:
        if uuid.UUID(rid).version != 4:
            bad.append("id is not a UUIDv4")
    except ValueError:
        bad.append("id is not a UUID")
    if rid in seen and seen[rid] != path:
        bad.append(f"id already used by {seen[rid].relative_to(ROOT)}")
    seen[rid] = path
    if str(rule.get("level", "")).lower() not in LEVELS:
        bad.append("level must be critical, high or medium (lower is not read in triage)")
    if str(rule.get("status", "")).lower() not in STATUSES:
        bad.append("status must be experimental, test or stable")
    fps = rule.get("falsepositives") or []
    if not isinstance(fps, list) or not fps or any(
            str(x).strip().lower().rstrip(".") in VAGUE_FP for x in fps):
        bad.append("falsepositives must name concrete legitimate cases, not `unknown`")
    values = leaves(rule.get("detection") or {})
    # Loopback and 0.0.0.0 are behaviour (\\127.0.0.1\ADMIN$, a bind address), not IOCs.
    iocs = sorted({m for v in values for m in IPV4.findall(v) + HASH.findall(v)
                   if not m.startswith(("127.", "0.0.0.0"))})
    if iocs:
        bad.append(f"IOC in detection ({', '.join(iocs[:3])}): detect behaviour, not indicators")
    bad += source_problems(rule)
    folder, why = expected_folder(rule.get("logsource") or {})
    if folder is None:
        bad.append(why)
    elif path.parent.is_relative_to(RULES) and path.parent.relative_to(RULES) != folder:
        bad.append(f"belongs in rules/{folder.as_posix()}/")
    try:
        parsed = SigmaCollection.from_yaml(text)
        for r in parsed.rules:
            for name, v in validators.items():
                try:
                    for issue in v().validate(r):
                        bad.append(f"pySigma {name}: {issue}")
                except Exception:  # noqa: BLE001 - a validator that cannot run is not the rule's fault
                    pass
    except Exception as e:  # noqa: BLE001
        return bad + [f"pySigma cannot parse it: {e}"]

    tests = [(kind, spec, event_of(spec)) for kind, spec in TEST.findall(text)]
    yes = [t for t in tests if t[0] == "match"]
    no = [t for t in tests if t[0] == "nomatch"]
    if len(yes) < 2 or not no:
        bad.append(f"needs 2+ `# test-match:` and 1+ `# test-nomatch:` "
                   f"(has {len(yes)} and {len(no)})")
    hit_words = set().union(*(words(e) for _, _, e in yes)) if yes else set()
    for _, spec, e in no:
        if yes and not words(e) & hit_words:
            bad.append(f"test-nomatch is not a near miss (shares no word with a "
                       f"test-match; show the legitimate use of the same tool): {spec}")
    benign = benign_events(folder) if folder is not None else []
    try:
        got = evaluate(text, [e for _, _, e in tests] + [e for _, e in benign])
    except Exception as e:  # noqa: BLE001
        return bad + [f"tests could not run: {e}"]
    for (kind, spec, _), g in zip(tests, got):
        if g != (kind == "match"):
            bad.append(f"test-{kind} failed: {spec}")
    for (line, _), g in zip(benign, got[len(tests):]):
        if g:
            bad.append(f"matches the benign corpus (tests/benign/{folder.as_posix()}.txt): {line}")

    mine = pairs(rule.get("detection") or {})
    if folder is not None and mine:
        for other, (ofolder, ovalues) in corpus.items():
            if other == path or ofolder != folder or not ovalues:
                continue
            share = overlap_share(mine, ovalues, hq)
            if share >= OVERLAP:
                bad.append(f"overlaps {other.relative_to(ROOT).as_posix()} ({share:.0%} of "
                           f"the detection values): improve that rule, keeping its id")
    return bad


class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):  # lists indented under keys
        return super().increase_indent(flow, False)


def slug(title: str) -> str:
    words_ = re.findall(r"[a-z0-9]+", title.lower())
    return "-".join(words_[:6]) or "rule"


def fix(path: Path) -> Path:
    """Normalise one rule file in place (see the module docstring); returns its
    path, renamed when the name was not the expected one."""
    import datetime
    raw = path.read_text(encoding="utf-8")
    raw = re.sub(r"^\s*```[a-zA-Z]*\s*$", "", raw, flags=re.M)
    comments = [ln for ln in raw.splitlines() if ln.startswith("#")]
    rule = yaml.safe_load(raw) or {}
    try:
        if uuid.UUID(str(rule.get("id", ""))).version != 4:
            raise ValueError
    except ValueError:
        rule["id"] = str(uuid.uuid4())
    rule.setdefault("status", "experimental")
    rule.setdefault("date", datetime.date.today().isoformat())
    for k in ("date", "modified"):
        if isinstance(rule.get(k), datetime.date):
            rule[k] = rule[k].isoformat()
    ordered = {k: rule[k] for k in ORDER if k in rule}
    ordered.update({k: v for k, v in rule.items() if k not in ordered})
    body = yaml.dump(ordered, Dumper=_Dumper, sort_keys=False, allow_unicode=True,
                     width=4096, default_flow_style=False)
    ls = rule.get("logsource") or {}
    product = (ls.get("product") or ("web" if ls.get("category") == "webserver" else "x"))
    kind = (ls.get("category") or ls.get("service") or "syslog").replace("-", "_")
    name = f"{str(rule['date'])[:10]}_{product}_{kind}_{slug(str(rule.get('title', '')))}.yml"
    target = path if NAME.match(path.name) else path.with_name(name.lower())
    target.write_text(body + ("\n".join(comments) + "\n" if comments else ""), encoding="utf-8")
    if target != path:
        path.unlink()
    return target


def main(argv: list[str]) -> int:
    hq_dir = os.environ.get("SIGMAHQ_DIR", "")
    if "--sigmahq" in argv:
        i = argv.index("--sigmahq")
        hq_dir = argv[i + 1] if i + 1 < len(argv) else ""
        argv = argv[:i] + argv[i + 2:]
        if not hq_dir:
            print("--sigmahq needs the SigmaHQ clone's folder")
            return 2
    hq = None
    if hq_dir:
        if not (Path(hq_dir) / "rules").is_dir():
            print(f"SigmaHQ {hq_dir}: not a SigmaHQ clone (no rules/ folder)")
            return 2
        hq = SigmaHQ(Path(hq_dir))
        print(f"SigmaHQ: {hq.rules} rules")
    if argv[:1] == ["--fix"]:
        argv = [str(fix(Path(a).resolve())) for a in argv[1:]]
        if not argv:
            print("--fix needs the file(s) to normalise")
            return 2
    paths = [Path(a).resolve() for a in argv] or sorted(RULES.rglob("*.yml"))
    seen: dict[str, Path] = {}
    corpus: dict[Path, tuple[Path | None, set[str]]] = {}
    for p in RULES.rglob("*.yml"):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if argv:  # ids of the rules not under check still count for uniqueness
            seen.setdefault(str(d.get("id", "")), p.resolve())
        corpus[p.resolve()] = (expected_folder(d.get("logsource") or {})[0],
                               pairs(d.get("detection") or {}))
    # An improved rule (same id as a file already here) is not its own duplicate.
    by_id = {str((yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("id", "")): p
             for p in corpus}
    failed = warned = 0
    for p in paths:
        rid = str((yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("id", ""))
        others = {k: v for k, v in corpus.items() if k != by_id.get(rid)}
        if by_id.get(rid) not in (None, p):
            seen.pop(rid, None)
        bad = check(p, seen, others, hq)
        text = p.read_text(encoding="utf-8")
        warn = [] if bad else sigmahq_warnings(text, yaml.safe_load(text) or {}, hq)
        try:
            shown = p.relative_to(ROOT).as_posix()
        except ValueError:
            shown = str(p)
        print(f"{'FAIL' if bad else 'ok  '} {shown}")
        for b in bad:
            print(f"     - {b}")
        for w in warn:
            print(f"warn - {w}")
        warned += any(w.startswith(DUPLICATE) for w in warn)
        failed += bool(bad)
    print(f"{len(paths) - failed} ok, {failed} failed"
          + (f", {warned} likely duplicates of SigmaHQ" if hq is not None else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
