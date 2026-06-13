import logging
import os
import stat

log = logging.getLogger(__name__)


def check_dir_permissions(watch_dir: str) -> str | None:
    """
    Check watch directory permissions.
    Returns error string if world-writable (must refuse to watch), None if OK.
    """
    try:
        st = os.lstat(watch_dir)
    except OSError as e:
        return f"Cannot stat watch directory {watch_dir!r}: {e}"

    if not stat.S_ISDIR(st.st_mode):
        return f"{watch_dir!r} is not a directory"

    if st.st_mode & stat.S_IWOTH:
        return (
            f"Watch directory {watch_dir!r} is world-writable "
            f"(mode={oct(stat.S_IMODE(st.st_mode))}).\n"
            f"  An attacker could create fake console sockets.\n"
            f"  Users may unknowingly send credentials to a rogue stream.\n"
            f"  Fix: chmod 0750 {watch_dir} && "
            f"chown root:_vnctlsd {watch_dir}\n"
            f"  Refusing to watch this directory."
        )

    if st.st_mode & stat.S_IROTH:
        log.warning(
            "Watcher: directory %r is world-readable (mode=%s). "
            "Socket names (VM names) are visible to all local users.",
            watch_dir, oct(stat.S_IMODE(st.st_mode)))

    return None


def validate_socket(path: str, trusted_uid: int | None) -> str | None:
    """
    Validate a socket file before accepting it.
    Returns None if valid, error string if not.
    Does not follow symlinks.
    """
    try:
        st = os.lstat(path)
    except OSError as e:
        return f"lstat failed: {e}"

    if not stat.S_ISSOCK(st.st_mode):
        return f"not a socket (mode={oct(stat.S_IMODE(st.st_mode))})"

    if trusted_uid is not None and st.st_uid != trusted_uid:
        return (f"owned by uid={st.st_uid}, expected uid={trusted_uid}. "
                f"Check that QEMU runs as the correct user.")

    if st.st_mode & stat.S_IWOTH:
        return ("world-writable socket. "
                "Use filesystem ACLs for group access instead.")

    return None
