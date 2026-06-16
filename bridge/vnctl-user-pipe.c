/*
 * vnctl-user-pipe — setuid helper for the vnctlsd PAM bridge.
 *
 * Install:
 *   cc -O2 -Wall -Wextra -o vnctl-user-pipe vnctl-user-pipe.c -lseccomp
 *   install -m 4750 -o root -g _vnctlsd vnctl-user-pipe /usr/libexec/
 *
 * The PAM bridge (running as _vnctlsd) forks a child that execs this binary
 * with stdin/stdout wired to the client socket.  The setuid bit gives the
 * child effective root briefly; it uses that window only to drop to the
 * authenticated user's identity.  After the drop, it locks itself down with
 * NO_NEW_PRIVS, landlock (deny all filesystem access), and seccomp (allowlist
 * of I/O syscalls), then pipes stdin/stdout to the vnctlsd Unix socket.
 *
 * vnctlsd identifies the connecting user via SO_PEERCRED, which the kernel
 * fills with this process's uid after the privilege drop.  No credential or
 * claim is ever sent over the socket.
 *
 * Security requirements:
 *   - Caller's real uid must equal the _vnctlsd system account uid.
 *   - Only --user USERNAME is accepted; no other arguments.
 *   - USERNAME must match [a-zA-Z0-9._-]{1,64} and must not map to uid 0.
 *   - Privilege drop is verified: setuid(0) must fail with EPERM.
 *   - connect() runs AFTER setuid() so SO_PEERCRED reports the target uid.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/landlock.h>
#include <poll.h>
#include <pwd.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Compile-time configuration — no run-time paths accepted. */
#define DAEMON_SOCKET   "/run/vnctlsd/vnctlsd.sock"
#define BRIDGE_USER     "_vnctlsd"
#define BUFSIZE         65536
#define MAX_USERNAME    64

/* Landlock syscall numbers.  Defined in <sys/syscall.h> on kernel ≥ 5.13;
 * fall back to x86-64 values (identical on arm64, riscv64, s390x). */
#ifndef __NR_landlock_create_ruleset
# define __NR_landlock_create_ruleset   444
# define __NR_landlock_add_rule         445
# define __NR_landlock_restrict_self    446
#endif

/* Landlock access rights added in each ABI version.
 * Guard with #ifndef so older kernel headers don't break the build. */
#ifndef LANDLOCK_ACCESS_FS_REFER
# define LANDLOCK_ACCESS_FS_REFER       (1ULL << 13)  /* ABI v2, kernel 5.19 */
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
# define LANDLOCK_ACCESS_FS_TRUNCATE    (1ULL << 14)  /* ABI v3, kernel 6.2  */
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
# define LANDLOCK_ACCESS_FS_IOCTL_DEV  (1ULL << 15)  /* ABI v5, kernel 6.10 */
#endif

/* V1 base rights (kernel 5.13, bits 0-12). */
#define LANDLOCK_FS_V1 ( \
    LANDLOCK_ACCESS_FS_EXECUTE      | \
    LANDLOCK_ACCESS_FS_WRITE_FILE   | \
    LANDLOCK_ACCESS_FS_READ_FILE    | \
    LANDLOCK_ACCESS_FS_READ_DIR     | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR   | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE  | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR    | \
    LANDLOCK_ACCESS_FS_MAKE_DIR     | \
    LANDLOCK_ACCESS_FS_MAKE_REG     | \
    LANDLOCK_ACCESS_FS_MAKE_SYM     | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK    | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO    | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK   )

/* ---------------------------------------------------------------------------
 * Error helpers
 * ------------------------------------------------------------------------- */

static __attribute__((noreturn)) void
die(const char *ctx)
{
    fprintf(stderr, "vnctl-user-pipe: %s: %s\n", ctx, strerror(errno));
    exit(1);
}

static __attribute__((noreturn)) void
die_msg(const char *msg)
{
    fprintf(stderr, "vnctl-user-pipe: %s\n", msg);
    exit(1);
}

/* ---------------------------------------------------------------------------
 * Username validation
 * ------------------------------------------------------------------------- */

static int
valid_username(const char *s)
{
    size_t n = 0;
    if (!s || !*s)
        return 0;
    for (; *s; s++, n++) {
        if (n >= MAX_USERNAME)
            return 0;
        if (!isalnum((unsigned char)*s) &&
            *s != '.' && *s != '_' && *s != '-')
            return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * Daemon socket path validation
 *
 * Checks are done with lstat() before connect() to reduce the TOCTOU window.
 * The residual risk is bounded by the parent-directory invariants below: only
 * root can create or replace files in a root-owned, non-writable directory.
 * ------------------------------------------------------------------------- */

static void
check_daemon_socket(const char *path)
{
    char dir[256];
    struct stat st;

    /* Extract parent directory. */
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir)
        *slash = '\0';
    else
        strcpy(dir, ".");

    if (lstat(dir, &st) != 0)
        die("stat socket directory");
    if (st.st_uid != 0)
        die_msg("daemon socket directory not owned by root");
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        die_msg("daemon socket directory is group- or world-writable");

    if (lstat(path, &st) != 0)
        die("stat daemon socket");
    if (S_ISLNK(st.st_mode))
        die_msg("daemon socket is a symlink");
    if (!S_ISSOCK(st.st_mode))
        die_msg("daemon socket is not a socket");
    if (st.st_uid != 0)
        die_msg("daemon socket not owned by root");
}

/* ---------------------------------------------------------------------------
 * Privilege drop
 * ------------------------------------------------------------------------- */

static void
drop_privs(const struct passwd *pw)
{
    int ngroups = (int)sysconf(_SC_NGROUPS_MAX);
    if (ngroups <= 0)
        ngroups = 65536;

    gid_t *gids = malloc((size_t)ngroups * sizeof(gid_t));
    if (!gids)
        die("malloc");

    if (getgrouplist(pw->pw_name, pw->pw_gid, gids, &ngroups) == -1) {
        /* Buffer too small — fall back to primary gid only. */
        ngroups = 1;
        gids[0] = pw->pw_gid;
    }

    /* Order matters: setgroups → setgid → setuid. */
    if (setgroups((size_t)ngroups, gids) != 0)
        die("setgroups");
    free(gids);

    if (setgid(pw->pw_gid) != 0)
        die("setgid");
    if (setuid(pw->pw_uid) != 0)
        die("setuid");

    /* Verify the drop is permanent. */
    if (setuid(0) != -1 || errno != EPERM)
        die_msg("privilege drop verification failed — setuid(0) succeeded");
}

/* ---------------------------------------------------------------------------
 * Landlock: deny all filesystem access.  Fails closed — a setuid helper must
 * not run without filesystem isolation on kernels that support it.
 * ------------------------------------------------------------------------- */

static void
apply_landlock(void)
{
    struct landlock_ruleset_attr attr = {0};

    /* Probe ABI version using the documented form: NULL attr, 0 size. */
    int abi = (int)syscall(__NR_landlock_create_ruleset,
                           NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP)
            die_msg("landlock required but unavailable (need Linux ≥ 5.13)");
        die("landlock_create_ruleset version probe");
    }

    /* Build the rights mask from the detected ABI version.  Only include
     * rights the kernel knows so the create-ruleset call does not get EINVAL
     * for unknown bits. */
    uint64_t fs_rights = LANDLOCK_FS_V1;
    if (abi >= 2) fs_rights |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 4) fs_rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    attr.handled_access_fs = fs_rights;

    int fd = (int)syscall(__NR_landlock_create_ruleset,
                          &attr, sizeof(attr), 0);
    if (fd < 0)
        die("landlock_create_ruleset");

    /* No rules added → empty allowlist → all filesystem access denied. */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("prctl NO_NEW_PRIVS (landlock pre-step)");

    if (syscall(__NR_landlock_restrict_self, fd, 0) != 0)
        die("landlock_restrict_self");

    close(fd);
}

/* ---------------------------------------------------------------------------
 * Seccomp: allowlist of I/O-only syscalls
 * ------------------------------------------------------------------------- */

static void
apply_seccomp(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx)
        die("seccomp_init");

#define ALLOW(name) \
    do { \
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 0) != 0) \
            die("seccomp_rule_add(" #name ")"); \
    } while (0)

    /* Core I/O and socket operations. */
    ALLOW(read);
    ALLOW(write);
    ALLOW(poll);
    ALLOW(ppoll);
    ALLOW(select);
    ALLOW(pselect6);
    ALLOW(shutdown);
    ALLOW(close);
    ALLOW(recvfrom);
    ALLOW(sendto);
    ALLOW(recvmsg);
    ALLOW(sendmsg);

    /* Process lifecycle. */
    ALLOW(exit);
    ALLOW(exit_group);
    ALLOW(rt_sigreturn);
    ALLOW(restart_syscall);

    /* glibc internals used from the buffer-copy path.
     * clock_gettime64 is a 32-bit ARM compat syscall and absent on x86-64;
     * clock_gettime covers all platforms we target. */
    ALLOW(brk);
    ALLOW(mmap);
    ALLOW(munmap);
    ALLOW(mprotect);
    ALLOW(futex);
    ALLOW(clock_gettime);
    ALLOW(getpid);
    ALLOW(gettid);

#undef ALLOW

    if (seccomp_load(ctx) != 0)
        die("seccomp_load");
    seccomp_release(ctx);
}

/* ---------------------------------------------------------------------------
 * Close all open file descriptors above stderr
 * ------------------------------------------------------------------------- */

static void
close_extra_fds(int keep_fd)
{
    int maxfd;
    errno = 0;
    maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd <= 0)
        maxfd = 1024;

    /* Prefer /proc/self/fd: avoids a scan of all possible fd numbers. */
    DIR *dirp = opendir("/proc/self/fd");
    if (dirp) {
        int dir_fd = dirfd(dirp);
        struct dirent *ent;
        while ((ent = readdir(dirp)) != NULL) {
            if (ent->d_name[0] == '.')
                continue;
            int fd = atoi(ent->d_name);
            if (fd >= 3 && fd != keep_fd && fd != dir_fd)
                close(fd);
        }
        closedir(dirp);
        return;
    }

    for (int fd = 3; fd < maxfd; fd++) {
        if (fd == keep_fd)
            continue;
        close(fd);
    }
}

/* ---------------------------------------------------------------------------
 * I/O bridge: stdin/stdout ↔ Unix socket
 * ------------------------------------------------------------------------- */

static void
bridge(int sock_fd)
{
    char buf[BUFSIZE];
    struct pollfd fds[2];
    fds[0].fd     = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd     = sock_fd;
    fds[1].events = POLLIN;

    for (;;) {
        int n = poll(fds, 2, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        /* POLLERR or POLLNVAL on either fd means we cannot recover. */
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLNVAL))
            break;

        if (fds[1].revents & (POLLIN | POLLHUP)) {
            ssize_t r;
            do { r = read(sock_fd, buf, sizeof(buf)); } while (r == -1 && errno == EINTR);
            if (r <= 0)
                break;
            ssize_t w = 0;
            while (w < r) {
                ssize_t s;
                do { s = write(STDOUT_FILENO, buf + w, (size_t)(r - w)); } while (s == -1 && errno == EINTR);
                if (s <= 0)
                    goto done;
                w += s;
            }
        }

        if (fds[0].revents & (POLLIN | POLLHUP)) {
            ssize_t r;
            do { r = read(STDIN_FILENO, buf, sizeof(buf)); } while (r == -1 && errno == EINTR);
            if (r <= 0)
                break;
            ssize_t w = 0;
            while (w < r) {
                ssize_t s;
                do { s = write(sock_fd, buf + w, (size_t)(r - w)); } while (s == -1 && errno == EINTR);
                if (s <= 0)
                    goto done;
                w += s;
            }
        }
    }

done:
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);
}

/* ---------------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    /* ---- 1. Minimal safe environment ------------------------------------ */
    clearenv();
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    umask(0077);

    /* ---- 2. Verify caller is _vnctlsd ----------------------------------- */
    struct passwd *bridge_pw = getpwnam(BRIDGE_USER);
    if (!bridge_pw)
        die_msg("cannot resolve " BRIDGE_USER " account");

    uid_t real_uid = getuid();   /* real uid; unaffected by the setuid bit */
    if (real_uid != bridge_pw->pw_uid)
        die_msg("caller is not " BRIDGE_USER);

    /* ---- 3. Parse arguments --------------------------------------------- */
    if (argc != 3 || strcmp(argv[1], "--user") != 0)
        die_msg("usage: vnctl-user-pipe --user USERNAME");

    const char *username = argv[2];
    if (!valid_username(username))
        die_msg("invalid username");

    /* ---- 4. Resolve target user ----------------------------------------- */
    struct passwd *target_pw = getpwnam(username);
    if (!target_pw)
        die_msg("unknown user");
    if (target_pw->pw_uid == 0)
        die_msg("target user is root — not permitted");

    /* Copy fields we need before any further getpwnam() call could clobber
     * the static buffer. */
    uid_t target_uid = target_pw->pw_uid;
    gid_t target_gid = target_pw->pw_gid;
    char pw_name[256];
    strncpy(pw_name, target_pw->pw_name, sizeof(pw_name) - 1);
    pw_name[sizeof(pw_name) - 1] = '\0';

    struct passwd pw_copy = *target_pw;
    pw_copy.pw_name = pw_name;
    pw_copy.pw_uid  = target_uid;
    pw_copy.pw_gid  = target_gid;

    /* ---- 5. Validate daemon socket -------------------------------------- */
    /* Done while still root so lstat() on a tight-permission directory
     * succeeds, and so the TOCTOU window is bounded: after this check only
     * root can replace something in /run/vnctlsd (enforced by the dir-owner
     * check inside). */
    check_daemon_socket(DAEMON_SOCKET);

    /* ---- 6. Drop privileges to target user ------------------------------ */
    /* Effective root (from the setuid bit) is consumed here and here only.
     * After this call the process is permanently target_uid. */
    drop_privs(&pw_copy);

    /* ---- 7. Connect to daemon socket (as target user) ------------------- */
    /* connect() runs AFTER setuid() so SO_PEERCRED on the server side reports
     * target_uid, not 0.  The daemon socket is mode 0666 so any uid can
     * connect; access control is done server-side via SO_PEERCRED. */
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        die("socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect " DAEMON_SOCKET);

    /* ---- 8. Close extra file descriptors -------------------------------- */
    close_extra_fds(sock_fd);

    /* ---- 9. NO_NEW_PRIVS ------------------------------------------------ */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("prctl NO_NEW_PRIVS");

    /* ---- 10. Landlock: deny all filesystem access ----------------------- */
    apply_landlock();

    /* ---- 11. Seccomp: allowlist I/O syscalls only ----------------------- */
    apply_seccomp();

    /* ---- 12. Bridge stdin/stdout ↔ daemon socket ----------------------- */
    bridge(sock_fd);

    return 0;
}
