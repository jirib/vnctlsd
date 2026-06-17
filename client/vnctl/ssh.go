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
// The SSH invocation is always:
//   <ssh-bin> [ssh-args] <server> vnctlsd-ssh-bridge
//
// -server  specifies [user@]host; -ssh-args passes extra SSH flags.
// No -t flag: vnctlsd-ssh-bridge is a raw pipe, not a terminal application,
// and a server-side pty would corrupt the console byte stream.
//
// Custom port:
//   vnctl -mode ssh -server host -ssh-args "-p 2222"
//
// ProxyJump:
//   vnctl -mode ssh -server host -ssh-args "-J bastion"
//
// Verbose with explicit login:
//   vnctl -mode ssh -server host -ssh-args "-v -l alice"

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const defaultSSHBin = "ssh"

func runSSH(server, sshBin, extraArgs string) {
	if server == "" {
		fmt.Fprintln(os.Stderr, "vnctl: -server is required for -mode ssh")
		os.Exit(1)
	}
	if err := validateSSHServer(server); err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: %v\n", err)
		os.Exit(1)
	}

	argv := strings.Fields(extraArgs)
	argv = append(argv, server, "vnctlsd-ssh-bridge")

	cmd := exec.Command(sshBin, argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "vnctl: ssh: %v\n", err)
		os.Exit(1)
	}
}

// validateSSHServer rejects host:port values — SSH takes the port via -p, not
// as part of the host argument.
func validateSSHServer(server string) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return nil // not a host:port — fine
	}
	hint := host
	if hint == "" {
		hint = "hostname"
	}
	return fmt.Errorf(
		"-server %q looks like a host:port address\n"+
			"  for -mode ssh use just the host (e.g. -server %q)\n"+
			"  to specify a non-standard port use -ssh-args (e.g. -ssh-args \"-p %s\")",
		server, hint, port)
}
