from pathlib import Path

from vnctlsd.acl import ACLResolver
from vnctlsd.config import ConsoleConfigStore, UserMapStore, load_console_config


def test_load_console_config_compiles_patterns_and_matches_socket(tmp_path: Path):
    cfg_path = tmp_path / "consoles.toml"
    cfg_path.write_text(
        """
[socket_validation]
trusted_uid = "1234"
watch_dir = "/run/vnctlsd"

[consoles.lab01]
type = "exec"
socket = "/run/vnctlsd/lab01.sock"
rw = ["ops"]

[[console_patterns]]
type = "qemu_unix"
socket_glob = "/run/vnctlsd/vm-{name}.sock"
console_name = "vm-{name}"
ro = ["students-{name}"]
""",
        encoding="utf-8",
    )

    store = ConsoleConfigStore(load_console_config(str(cfg_path)))

    explicit = store.match_socket("/run/vnctlsd/lab01.sock")
    assert explicit == (
        {
            "_console_name": "lab01",
            "type": "exec",
            "socket": "/run/vnctlsd/lab01.sock",
            "rw": ["ops"],
        },
        {},
    )

    pattern = store.match_socket("/run/vnctlsd/vm-alpha.sock")
    assert pattern is not None
    defn, vars_ = pattern
    assert defn["console_name"] == "vm-{name}"
    assert vars_ == {"name": "alpha"}
    assert store.resolve_trusted_uid(defn, vars_) == 1234
    assert store.get_watch_dir() == "/run/vnctlsd"


def test_user_map_role_prefers_read_write_over_read_only():
    users = UserMapStore(
        {
            "users": {"alice": {"groups": ["viewers", "operators"]}},
            "groups": {
                "viewers": {"role": "read_only"},
                "operators": {"role": "read_write"},
            },
        }
    )

    assert users.get_groups("alice") == ["viewers", "operators"]
    assert users.get_role("alice") == "read_write"
    assert users.get_role("missing") is None
    assert users.user_exists("alice") is True
    assert users.user_exists("missing") is False


def test_acl_console_lists_override_user_map_role_and_expand_templates():
    users = UserMapStore(
        {
            "users": {
                "alice": {"groups": ["lab-a"]},
                "bob": {"groups": ["students-alpha"]},
                "carol": {"groups": ["admins"]},
            },
            "groups": {
                "lab-a": {"role": "read_write"},
                "students-alpha": {"role": "read_only"},
                "admins": {"role": "read_write"},
            },
        }
    )
    acl = ACLResolver(users)
    console_def = {"rw": ["admins"], "ro": ["students-{name}"]}

    assert (
        acl.resolve_access("carol", "vm-alpha", console_def, {"name": "alpha"})
        == "read_write"
    )
    assert (
        acl.resolve_access("bob", "vm-alpha", console_def, {"name": "alpha"})
        == "read_only"
    )
    assert acl.resolve_access("alice", "vm-alpha", console_def, {"name": "alpha"}) is None


def test_acl_falls_back_to_user_map_when_console_has_no_lists():
    users = UserMapStore(
        {
            "users": {"alice": {"groups": ["operators"]}},
            "groups": {"operators": {"role": "read_write"}},
        }
    )
    acl = ACLResolver(users)

    assert acl.resolve_access("alice", "lab01", {}, {}) == "read_write"
    assert acl.resolve_access("missing", "lab01", {}, {}) is None
