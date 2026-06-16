package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// --- buildSSHArgv ---

func TestBuildSSHArgvExpandsServerToken(t *testing.T) {
	got, err := buildSSHArgv("console.example.com", "ssh {server} vnctlsd-ssh-bridge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ssh", "console.example.com", "vnctlsd-ssh-bridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestBuildSSHArgvExpandsServerTokenWithExtraFlags(t *testing.T) {
	got, err := buildSSHArgv("console.example.com", "ssh -p 2222 {server} vnctlsd-ssh-bridge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ssh", "-p", "2222", "console.example.com", "vnctlsd-ssh-bridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestBuildSSHArgvServerWithSpaceIsNotReSplit(t *testing.T) {
	// A server value containing a space must be kept as a single token, not
	// re-split by strings.Fields after substitution.
	got, err := buildSSHArgv("user name@host", "ssh {server} vnctlsd-ssh-bridge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ssh", "user name@host", "vnctlsd-ssh-bridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestBuildSSHArgvErrorOnMissingServerPlaceholder(t *testing.T) {
	_, err := buildSSHArgv("console.example.com", "ssh -s console.example.com vnctlsd")
	if err == nil {
		t.Fatal("expected error for template without {server}, got nil")
	}
	if !strings.Contains(err.Error(), "{server}") {
		t.Fatalf("error should mention {server}, got: %v", err)
	}
}

func TestBuildSSHArgvErrorOnEmptyTemplate(t *testing.T) {
	_, err := buildSSHArgv("host", "")
	if err == nil {
		t.Fatal("expected error for empty -ssh-args, got nil")
	}
}

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

func TestRunSSHInvokesConfiguredClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh shell script test requires a Unix shell")
	}

	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args.txt")
	sshPath := filepath.Join(tmp, "fake-ssh")
	// Record all argv (excluding $0) to a file and exit 0.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VNCTL_FAKE_SSH_ARGS\"\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("VNCTL_FAKE_SSH_ARGS", argsPath)

	// runSSH calls os.Exit only on non-zero exit or pre-exec failure.
	// The fake script exits 0 so runSSH returns normally here.
	runSSH("console.example.com", sshPath+" {server} vnctlsd-ssh-bridge")

	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.Fields(string(raw))
	// argv[0] (sshPath) is not in $@ — only the arguments are captured.
	want := []string{"console.example.com", "vnctlsd-ssh-bridge"}
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
	sshArgs := os.Getenv("VNCTL_SSH_TEST_ARGS")
	if sshArgs == "" {
		sshArgs = "ssh -o BatchMode=yes -o ConnectTimeout=5 {server} vnctlsd-ssh-bridge"
	}
	// runSSH calls os.Exit on SSH failure, which would kill the test process.
	// This test is intended for manual validation with a working server.
	runSSH(server, sshArgs)
}
