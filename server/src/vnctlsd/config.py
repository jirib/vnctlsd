import logging
import os
import pwd
import threading

from .glob_patterns import compile_glob_pattern, match_glob_pattern

log = logging.getLogger(__name__)


def load_console_config(path: str) -> dict:
    """
    Load consoles.yaml / consoles.toml.

    Returns a dict with keys: socket_validation, consoles, console_patterns.
    Glob patterns in console_patterns are pre-compiled.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML required: pip install pyyaml")
        with open(path, 'r') as fh:
            data = yaml.safe_load(fh) or {}
    elif ext == '.toml':
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise RuntimeError("tomli required: pip install tomli")
        with open(path, 'rb') as fh:
            data = tomllib.load(fh)
    else:
        raise ValueError(f"Unsupported format: {ext}")

    for pat in data.get('console_patterns', []):
        if 'socket_glob' in pat:
            fnmatch_pat, regex = compile_glob_pattern(pat['socket_glob'])
            pat['_fnmatch'] = fnmatch_pat
            pat['_regex'] = regex

    return data


class ConsoleConfigStore:
    """Thread-safe, hot-reloadable console configuration."""

    def __init__(self, initial: dict):
        self._cfg = initial
        self._lock = threading.RLock()

    def get(self) -> dict:
        with self._lock:
            return self._cfg

    def reload(self, path: str) -> dict:
        new_cfg = load_console_config(path)
        with self._lock:
            self._cfg = new_cfg
        return new_cfg

    def match_socket(self, socket_path: str) -> tuple[dict, dict] | None:
        """
        Find the console definition matching socket_path.
        Returns (definition, template_vars) or None.
        Checks explicit consoles first, then patterns.
        """
        with self._lock:
            cfg = self._cfg

        for name, defn in cfg.get('consoles', {}).items():
            if defn.get('socket') == socket_path:
                return dict(defn, _console_name=name), {}

        for pat in cfg.get('console_patterns', []):
            if '_fnmatch' not in pat:
                continue
            vars_ = match_glob_pattern(
                socket_path, pat['_fnmatch'], pat['_regex'])
            if vars_ is not None:
                return dict(pat), vars_

        return None

    def resolve_trusted_uid(self, defn: dict, vars_: dict) -> int | None:
        """
        Resolve trusted_uid from definition or global default.
        Template vars are substituted.  Returns numeric uid or None.
        """
        with self._lock:
            global_uid_name = (self._cfg
                               .get('socket_validation', {})
                               .get('trusted_uid', ''))

        uid_name = (defn.get('validation', {})
                    .get('trusted_uid', global_uid_name))

        if not uid_name:
            return None

        try:
            uid_name = uid_name.format(**vars_)
        except KeyError:
            pass

        try:
            return pwd.getpwnam(uid_name).pw_uid
        except KeyError:
            try:
                return int(uid_name)
            except ValueError:
                log.error("Cannot resolve trusted_uid %r to a uid", uid_name)
                return None

    def get_command(self, action: str) -> dict | None:
        """
        Return the command definition for action from the commands section.
        Returns None if the action is not defined.
        """
        with self._lock:
            return self._cfg.get('commands', {}).get(action)

    def get_all_commands(self) -> list[str]:
        with self._lock:
            return list(self._cfg.get('commands', {}).keys())

    def get_watch_dir(self) -> str:
        with self._lock:
            return (self._cfg
                    .get('socket_validation', {})
                    .get('watch_dir', '/run/vnctlsd/'))


def load_user_map(path: str) -> dict:
    """
    Load users.yaml / users.toml.

    Format:
      users:
        student01:
          groups: [lab-a]
      groups:
        lab-a:
          role: read_write
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML required: pip install pyyaml")
        with open(path, 'r') as fh:
            data = yaml.safe_load(fh) or {}
    elif ext == '.toml':
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise RuntimeError("tomli required: pip install tomli")
        with open(path, 'rb') as fh:
            data = tomllib.load(fh)
    else:
        raise ValueError(f"Unsupported format: {ext}")
    return data


class UserMapStore:
    """Thread-safe, hot-reloadable user/group map."""

    def __init__(self, initial: dict):
        self._map = initial
        self._lock = threading.RLock()

    def reload(self, path: str) -> dict:
        new_map = load_user_map(path)
        with self._lock:
            self._map = new_map
        return new_map

    def get_groups(self, username: str) -> list[str]:
        with self._lock:
            entry = self._map.get('users', {}).get(username, {})
            if isinstance(entry, dict):
                return list(entry.get('groups', []))
            return []

    def get_role(self, username: str) -> str | None:
        """
        Resolve the user's effective role from their group memberships.
        read_write takes priority over read_only if user is in both.
        Returns None if user has no groups or no role defined.
        """
        with self._lock:
            groups = self.get_groups(username)
            group_defs = self._map.get('groups', {})

        if not groups:
            return None

        roles = set()
        for g in groups:
            gdef = group_defs.get(g, {})
            role = gdef.get('role') if isinstance(gdef, dict) else None
            if role:
                roles.add(role)

        if not roles:
            return None
        if 'read_write' in roles:
            return 'read_write'
        return 'read_only'

    def user_exists(self, username: str) -> bool:
        with self._lock:
            return username in self._map.get('users', {})

    def get_map(self) -> dict:
        with self._lock:
            return dict(self._map)
