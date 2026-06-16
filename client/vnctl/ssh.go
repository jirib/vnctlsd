// SSH mode.
//
// Instead of a TLS connection, vnctl invokes an SSH client that runs
// vnctlsd-ssh-bridge on the remote host.  sshd authenticates the user (keys,
// certificates, MFA — whatever the site policy requires) and executes the
// command as that user.  The command connects to the daemon's trusted Unix
// socket and pipes stdin/stdout straight through; the daemon identifies the
// caller from the kernel-reported peer credentials (SO_PEERCRED) so no
// password is exchanged with vnctlsd itself.
//
// vnctlsd-ssh-bridge must be installed in PATH on the server (e.g. /usr/bin/).
// No sshd_config changes are required.
//
// The SSH binary and its arguments are controlled by -ssh-args (default below).
// {server} in any token is replaced with the -server value.  The SSH binary
// must appear first.  No -t flag: the command is a raw pipe, not a terminal
// application, and an extra server-side pty would corrupt the console byte stream.
//
// Custom port example:
//   vnctl -mode ssh -server user@host -ssh-args "ssh -p 2222 {server} vnctlsd-ssh-bridge"
//
// ProxyJump example:
//   vnctl -mode ssh -server host -ssh-args "ssh -J bastion {server} vnctlsd-ssh-bridge"

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// defaultSSHArgs is the SSH command template used when -ssh-args is not set.
// {server} is replaced with the -server value by buildSSHArgv.
// No -t: vnctlsd-ssh-bridge is a dumb pipe, not a pty application.
const defaultSSHArgs = "ssh {server} vnctlsd-ssh-bridge"

func runSSH(server, sshArgs string) {
	if server == "" {
		fmt.Fprintln(os.Stderr, "vnctl: -server is required for -mode ssh")
		os.Exit(1)
	}
	if err := validateSSHServer(server); err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: %v\n", err)
		os.Exit(1)
	}

	argv, err := buildSSHArgv(server, sshArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin  = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Propagate the SSH process exit code directly so callers and
			// shell scripts can distinguish auth failures, host-not-found,
			// clean disconnects, etc.
			os.Exit(exitErr.ExitCode())
		}
		// Pre-exec failure (binary not found, permission denied, …).
		fmt.Fprintf(os.Stderr, "vnctl: ssh: %v\n", err)
		os.Exit(1)
	}
}

// buildSSHArgv builds the argv for the SSH invocation.
//
// Each token in sshArgs is expanded independently: {server} within a token is
// replaced with server.  Because substitution happens per-token (not on the
// joined string), a server value containing spaces is passed as a single
// argument rather than being re-split by the shell.
//
// An error is returned if sshArgs is empty or no token contains {server}.
func buildSSHArgv(server, sshArgs string) ([]string, error) {
	tokens := strings.Fields(sshArgs)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("-ssh-args must not be empty")
	}

	out := make([]string, len(tokens))
	found := false
	for i, tok := range tokens {
		if strings.Contains(tok, "{server}") {
			out[i] = strings.ReplaceAll(tok, "{server}", server)
			found = true
		} else {
			out[i] = tok
		}
	}
	if !found {
		return nil, fmt.Errorf(
			"-ssh-args %q does not contain {server}; cannot insert %q\n"+
				"  hint: use e.g. \"ssh {server} vnctlsd-ssh-bridge\"",
			sshArgs, server)
	}
	return out, nil
}

// validateSSHServer rejects values that look like TLS-style host:port addresses.
// SSH does not accept that format; the port must be given with -p in -ssh-args.
func validateSSHServer(server string) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// Not a host:port — fine for SSH.
		return nil
	}
	hint := host
	if hint == "" {
		hint = "hostname"
	}
	return fmt.Errorf(
		"-server %q looks like a host:port address\n"+
			"  for -mode ssh use just the host (e.g. -server %q)\n"+
			"  to specify a non-standard port add it to -ssh-args (e.g. \"ssh -p %s {server} vnctlsd-ssh-bridge\")",
		server, hint, port)
}
