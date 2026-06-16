package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// --- validateSSHServer ---

func TestValidateSSHServerAcceptsPlainHost(t *testing.T) {
	if err := validateSSHServer("console.example.com"); err != nil {
		t.Fatalf("unexpected error for plain hostname: %v", err)
	}
}

func TestValidateSSHServerAcceptsUserAtHost(t *testing.T) {
	if err := validateSSHServer("alice@console.example.com"); err != nil {
		t.Fatalf("unexpected error for user@host: %v", err)
	}
}

func TestValidateSSHServerRejectsHostPort(t *testing.T) {
	if err := validateSSHServer("console.example.com:8443"); err == nil {
		t.Fatal("expected error for host:port, got nil")
	}
}

func TestValidateSSHServerRejectsIPv6WithPort(t *testing.T) {
	if err := validateSSHServer("[::1]:22"); err == nil {
		t.Fatal("expected error for [::1]:22, got nil")
	}
}

// --- runSSH (integration with fake ssh binary) ---

func TestRunSSHInvokesSSHWithServerAndCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh shell script test requires a Unix shell")
	}

	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args.txt")
	sshPath := filepath.Join(tmp, "fake-ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VNCTL_FAKE_SSH_ARGS\"\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("VNCTL_FAKE_SSH_ARGS", argsPath)

	runSSH("console.example.com", sshPath, "")

	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	// argv[0] (sshPath) is excluded from $@ — only the arguments are captured.
	got := strings.Fields(string(raw))
	want := []string{"console.example.com", "vnctlsd-ssh-bridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ssh args = %#v, want %#v", got, want)
	}
}

func TestRunSSHPrependsExtraArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh shell script test requires a Unix shell")
	}

	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args.txt")
	sshPath := filepath.Join(tmp, "fake-ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VNCTL_FAKE_SSH_ARGS\"\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("VNCTL_FAKE_SSH_ARGS", argsPath)

	runSSH("host", sshPath, "-p 2222 -l alice")

	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.Fields(string(raw))
	want := []string{"-p", "2222", "-l", "alice", "host", "vnctlsd-ssh-bridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ssh args = %#v, want %#v", got, want)
	}
}

// TestSSHHandshakeAndAuthIntegration requires a real SSH server with
// vnctlsd-ssh-bridge installed in PATH.  Set VNCTL_SSH_TEST_SERVER and
// optionally VNCTL_SSH_TEST_ARGS to enable.
func TestSSHHandshakeAndAuthIntegration(t *testing.T) {
	server := os.Getenv("VNCTL_SSH_TEST_SERVER")
	if server == "" {
		t.Skip("set VNCTL_SSH_TEST_SERVER to run the real SSH handshake/auth test")
	}
	extraArgs := os.Getenv("VNCTL_SSH_TEST_ARGS")
	if extraArgs == "" {
		extraArgs = "-o BatchMode=yes -o ConnectTimeout=5"
	}
	// runSSH calls os.Exit on SSH failure, which would kill the test process.
	// This test is intended for manual validation with a working server.
	runSSH(server, defaultSSHBin, extraArgs)
}
