import pytest

from vnctlsd.glob_patterns import compile_glob_pattern, match_glob_pattern
from vnctlsd.output import apply_filter, render_normalized


def test_glob_pattern_captures_named_fields_without_crossing_directories():
    fnmatch_pat, regex = compile_glob_pattern("/run/vnctlsd/vm-{name}.sock")

    assert fnmatch_pat == "/run/vnctlsd/vm-*.sock"
    assert match_glob_pattern("/run/vnctlsd/vm-alpha.sock", fnmatch_pat, regex) == {
        "name": "alpha"
    }
    assert match_glob_pattern("/run/vnctlsd/vm-a/b.sock", fnmatch_pat, regex) is None


def test_apply_filter_renders_json_table_and_status_outputs():
    table = apply_filter(
        '{"state": "running", "vcpus": 2}',
        "json",
        {"type": "table", "rows": [["State", "{state}"], ["VCPUs", "{vcpus}"]]},
    )
    assert table == {"type": "table", "rows": [("State", "running"), ("VCPUs", "2")]}
    assert render_normalized(table) == "  State  running\r\n  VCPUs  2\r\n"

    status = apply_filter(
        "Domain is running",
        "raw",
        {"type": "status", "ok_if": "running", "message": "{output}"},
    )
    assert status == {"type": "status", "ok": True, "message": "Domain is running"}
    assert render_normalized(status) == "\u2713 Domain is running\r\n"


def test_apply_filter_handles_lines_and_json_parse_errors():
    listed = apply_filter("alpha\n\n beta \n", "lines", None)
    assert listed == {"type": "list", "items": ["alpha", " beta "]}
    assert render_normalized({"type": "list", "items": []}) == "(empty)\r\n"

    parsed = apply_filter("{not json", "json", None)
    assert parsed["type"] == "string"
    assert parsed["value"].startswith("[parse error:")


def test_render_normalized_unknown_type_falls_back_to_string():
    assert render_normalized({"type": "custom", "value": 1}) == (
        "{'type': 'custom', 'value': 1}\r\n"
    )
