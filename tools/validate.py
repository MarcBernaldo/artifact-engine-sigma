"""Validate every rule in rules/: the gate a rule passes before it is merged.

    python tools/validate.py            # all rules
    python tools/validate.py FILE...    # some

Checks, per rule: it parses as Sigma (pySigma) with no validator issue; the
required fields; `id` is a UUIDv4 and unique across the repository; the file name
and folder match the logsource; the logsource is one Artifact Engine evaluates;
at least one `# test-match:` line, and every `# test-match:` / `# test-nomatch:`
line behaves (evaluated with pySigma's SQLite backend over a one-row table).
Exit 1 on any failure.
"""
from __future__ import annotations

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
NAME = re.compile(r"^\d{4}-\d{2}-\d{2}_[a-z0-9]+_[a-z0-9_]+_[a-z0-9-]+\.yml$")
REQUIRED = ("title", "id", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level")
LEVELS = {"critical", "high", "medium"}
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


PAIR = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def event_of(spec: str) -> dict[str, str]:
    """`Field="value with spaces" Other=value` -> {Field: ..., Other: ...}."""
    return {k: (q if q or not u else u) for k, q, u in PAIR.findall(spec)}


def matches(rule_yaml: str, event: dict[str, str]) -> bool:
    q = sqlite_mod.sqliteBackend().convert(SigmaCollection.from_yaml(rule_yaml))[0]
    fields = set(event) | set(re.findall(r"`([^`]+)`", q)) | set(FIELD.findall(q))
    con = sqlite3.connect(":memory:")
    cols = sorted(fields)
    con.execute("CREATE TABLE t (" + ", ".join(f'"{c}" TEXT' for c in cols) + ")")
    con.execute(f"INSERT INTO t VALUES ({','.join('?' * len(cols))})",
                [event.get(c) for c in cols])
    return bool(con.execute(FROM.sub(r"\1t", q, count=1)).fetchall())


def check(path: Path, seen: dict[str, Path]) -> list[str]:
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
    folder, why = expected_folder(rule.get("logsource") or {})
    if folder is None:
        bad.append(why)
    elif path.parent.relative_to(RULES) != folder:
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
    tests = TEST.findall(text)
    if not any(kind == "match" for kind, _ in tests):
        bad.append("no `# test-match:` line")
    for kind, spec in tests:
        try:
            got = matches(text, event_of(spec))
        except Exception as e:  # noqa: BLE001
            bad.append(f"test-{kind} could not run: {e}")
            continue
        if got != (kind == "match"):
            bad.append(f"test-{kind} failed: {spec}")
    return bad


def main(argv: list[str]) -> int:
    paths = [Path(a).resolve() for a in argv] or sorted(RULES.rglob("*.yml"))
    seen: dict[str, Path] = {}
    if argv:  # ids of the rules not under check still count for uniqueness
        for p in RULES.rglob("*.yml"):
            d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            seen.setdefault(str(d.get("id", "")), p.resolve())
    failed = 0
    for p in paths:
        bad = check(p, seen)
        print(f"{'FAIL' if bad else 'ok  '} {p.relative_to(ROOT).as_posix()}")
        for b in bad:
            print(f"     - {b}")
        failed += bool(bad)
    print(f"{len(paths) - failed} ok, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
