import logging

from .config import UserMapStore

log = logging.getLogger(__name__)


class ACLResolver:
    """
    Determines whether a user can access a console and in what mode.

    resolve_access(username, console_name, console_def, template_vars)
      → 'read_write' | 'read_only' | None (denied)

    Resolution order:
      1. console definition rw/ro lists (explicit or pattern-derived)
         - list entries can be usernames, group names, or '*'
         - template vars substituted (e.g. rw: ["{name}"] → rw: ["vm-lab01"])
      2. user's group role (from user map)

    Console definition wins if it has explicit rw/ro entries.
    User map role is the fallback.
    """

    def __init__(self, user_map: UserMapStore):
        self._user_map = user_map

    def resolve_access(self, username: str, console_name: str,
                       console_def: dict, template_vars: dict) -> str | None:
        if not self._user_map.user_exists(username):
            return None

        user_groups = set(self._user_map.get_groups(username))

        def matches_principal(principals: list[str]) -> bool:
            for p in principals:
                try:
                    p_resolved = p.format(**template_vars)
                except KeyError:
                    p_resolved = p
                if p_resolved == '*':
                    return True
                if p_resolved == username:
                    return True
                if p_resolved in user_groups:
                    return True
            return False

        rw_list = console_def.get('rw', [])
        ro_list = console_def.get('ro', [])

        if rw_list or ro_list:
            if matches_principal(rw_list):
                return 'read_write'
            if matches_principal(ro_list):
                return 'read_only'
            return None

        return self._user_map.get_role(username)
