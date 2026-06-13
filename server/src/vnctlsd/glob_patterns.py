import fnmatch
import re


def compile_glob_pattern(glob_str: str) -> tuple[str, re.Pattern]:
    """
    Convert a glob string with {name} placeholders to:
    - an fnmatch pattern (for fast pre-filtering)
    - a regex (for capture extraction)

    Example:
      "/run/vnctlsd/console-{name}.sock"
      → fnmatch: "/run/vnctlsd/console-*.sock"
      → regex:   r"^/run/vnctlsd/console-(?P<name>[^/]+)[.]sock$"
    """
    fnmatch_pat = re.sub(r'\{[^}]+\}', '*', glob_str)

    escaped = re.escape(glob_str)
    regex_str = re.sub(
        r'\\{([^}]+)\\}',
        lambda m: f'(?P<{m.group(1)}>[^/]+)',
        escaped
    )
    regex = re.compile(f'^{regex_str}$')
    return fnmatch_pat, regex


def match_glob_pattern(path: str, fnmatch_pat: str,
                       regex: re.Pattern) -> dict | None:
    """Returns dict of captured variables if path matches, else None."""
    if not fnmatch.fnmatch(path, fnmatch_pat):
        return None
    m = regex.match(path)
    if not m:
        return None
    return m.groupdict()
