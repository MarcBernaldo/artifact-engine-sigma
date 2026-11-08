"""The SigmaHQ checks of tools/validate.py, against a small SigmaHQ-shaped folder."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import validate as V  # noqa: E402

PROC = "logsource:\n  product: windows\n  category: process_creation\n"


def hq_rule(title: str, detection: str, logsource: str = PROC) -> str:
    return f"title: {title}\nid: 00000000-0000-4000-8000-{abs(hash(title)) % 10**12:012d}\n" \
           f"status: test\n{logsource}detection:\n{detection}level: high\n"


@pytest.fixture
def hq(tmp_path: Path) -> V.SigmaHQ:
    rules = tmp_path / "rules" / "windows" / "process_creation"
    rules.mkdir(parents=True)
    files = {
        # A filter on a field the test events never carry.
        "fsutil.yml": hq_rule("Fsutil Journal", (
            "  selection:\n    CommandLine|contains: deletejournal\n"
            "  filter:\n    ParentImage|endswith: '\\explorer.exe'\n"
            "  condition: selection and not filter\n")),
        # Needs both values: PowerShell alone is not it.
        "enc.yml": hq_rule("Encoded PowerShell", (
            "  selection:\n    Image|endswith: '\\powershell.exe'\n"
            "    CommandLine|contains: ' -enc '\n  condition: selection\n")),
        "dep.yml": hq_rule("Deprecated Fsutil", (
            "  selection:\n    CommandLine|contains: usn\n  condition: selection\n"
        )).replace("status: test", "status: deprecated"),
    }
    # Common values: powershell.exe and wscript.exe in many rules.
    for i in range(30):
        files[f"common{i}.yml"] = hq_rule(f"Common {i}", (
            f"  selection:\n    Image|endswith:\n      - '\\powershell.exe'\n"
            f"      - '\\wscript.exe'\n    CommandLine|contains: marker{i}\n"
            "  condition: selection\n"))
    for name, text in files.items():
        (rules / name).write_text(text, encoding="utf-8")
    other = tmp_path / "rules" / "windows" / "builtin" / "system"
    other.mkdir(parents=True)
    (other / "svc.yml").write_text(hq_rule("Service Journal", (
        "  selection:\n    ImagePath|contains: deletejournal\n  condition: selection\n"),
        "logsource:\n  product: windows\n  service: system\n"), encoding="utf-8")
    return V.SigmaHQ(tmp_path)


def mine(*matches: str, extra: str = "") -> tuple[str, dict]:
    text = ("title: Mine\nid: 11111111-1111-4111-8111-111111111111\n" + PROC
            + "detection:\n  selection:\n    CommandLine|contains: x\n  condition: selection\n")
    text +="".join(f"# test-match: {m}\n" for m in matches) + extra
    return text, V.yaml.safe_load(text)


def test_sigmahq_detects_through_a_filter_on_a_missing_field(hq):
    text, rule = mine('CommandLine="fsutil usn deletejournal /D C:"',
                      'CommandLine="fsutil.exe usn deletejournal /n C:"')
    warn = V.sigmahq_warnings(text, rule, hq)
    assert any("Fsutil Journal" in w for w in warn)
    assert warn[-1].startswith(V.DUPLICATE)


def test_partial_coverage_names_the_rule_but_is_no_duplicate(hq):
    text, rule = mine('CommandLine="fsutil usn deletejournal /D C:"',
                      'CommandLine="fsutil behavior set SymlinkEvaluation R2R:1"')
    warn = V.sigmahq_warnings(text, rule, hq)
    assert warn == [w for w in warn if w.startswith("test-match 1 ")]
    assert len(warn) == 1


def test_shared_common_values_alone_are_no_hit(hq):
    text, rule = mine('Image="C:\\Windows\\System32\\powershell.exe" CommandLine="powershell -w hidden"',
                      'Image="C:\\Windows\\System32\\wscript.exe" CommandLine="wscript a.vbs"')
    assert V.sigmahq_warnings(text, rule, hq) == []


def test_other_logsource_and_deprecated_rules_do_not_count(hq):
    text, rule = mine('ImagePath="fsutil usn deletejournal"', 'CommandLine="fsutil usn x"')
    assert V.sigmahq_warnings(text, rule, hq) == []


def test_beyond_sigmahq_reason_replaces_the_duplicate_verdict(hq):
    text, rule = mine('CommandLine="fsutil usn deletejournal /D C:"',
                      'CommandLine="fsutil.exe usn deletejournal /n C:"',
                      extra="# beyond-sigmahq: also fires from prefetch\n")
    warn = V.sigmahq_warnings(text, rule, hq)
    assert not any(w.startswith(V.DUPLICATE) for w in warn)
    assert "also fires from prefetch" in warn[-1]


def test_without_sigmahq_nothing_is_checked():
    text, rule = mine('CommandLine="fsutil usn deletejournal"', 'CommandLine="x"')
    assert V.sigmahq_warnings(text, rule, None) == []


def test_overlap_weighs_values_by_rarity_in_sigmahq(hq):
    common_a = {"image=\\powershell.exe", "image=\\wscript.exe", "commandline=foo"}
    common_b = {"image=\\powershell.exe", "image=\\wscript.exe", "commandline=bar"}
    assert V.overlap_share(common_a, common_b) >= V.OVERLAP          # unweighted: 2/3
    assert V.overlap_share(common_a, common_b, hq) < V.OVERLAP       # common values ~0
    rare_a = {"commandline=deletejournal", "image=\\powershell.exe", "image=\\wscript.exe"}
    rare_b = {"commandline=deletejournal", "commandline=zzz-unique"}
    assert V.overlap_share(rare_a, rare_b) < V.OVERLAP               # unweighted: 1/2
    assert V.overlap_share(rare_a, rare_b, hq) >= V.OVERLAP          # the rare value counts


def test_main_refuses_a_folder_that_is_not_sigmahq(tmp_path, capsys):
    assert V.main(["--sigmahq", str(tmp_path)]) == 2
    assert "not a SigmaHQ clone" in capsys.readouterr().out
