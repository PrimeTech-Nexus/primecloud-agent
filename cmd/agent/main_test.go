package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	origVersion := Version
	origCommit := CommitSHA
	defer func() {
		Version = origVersion
		CommitSHA = origCommit
	}()

	tests := []struct {
		name     string
		version  string
		commit   string
		expected string
	}{
		{
			name:     "development default without commit",
			version:  "dev",
			commit:   "none",
			expected: "primecloud-agent dev",
		},
		{
			name:     "empty commit string",
			version:  "dev",
			commit:   "",
			expected: "primecloud-agent dev",
		},
		{
			name:     "tagged release with commit",
			version:  "v0.4.0",
			commit:   "1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c",
			expected: "primecloud-agent v0.4.0 (commit: 1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c)",
		},
		{
			name:     "semver without v prefix with short commit",
			version:  "0.4.0",
			commit:   "1ac48ec",
			expected: "primecloud-agent 0.4.0 (commit: 1ac48ec)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			CommitSHA = tt.commit
			got := formatVersion()
			if got != tt.expected {
				t.Errorf("formatVersion() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestRun_VersionFlags(t *testing.T) {
	origVersion := Version
	origCommit := CommitSHA
	defer func() {
		Version = origVersion
		CommitSHA = origCommit
	}()

	Version = "v0.4.0"
	CommitSHA = "1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c"
	expectedOutput := "primecloud-agent v0.4.0 (commit: 1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c)\n"

	flagVariants := []string{
		"--version",
		"-version",
		"-v",
		"--v",
	}

	for _, flag := range flagVariants {
		t.Run("flag_"+flag, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := run([]string{flag}, &stdout, &stderr)

			if exitCode != 0 {
				t.Fatalf("run([%q]) returned exit code %d, expected 0", flag, exitCode)
			}
			if stdout.String() != expectedOutput {
				t.Errorf("stdout = %q, expected %q", stdout.String(), expectedOutput)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, expected empty", stderr.String())
			}
			// Confirm banner was NOT printed on version check
			if strings.Contains(stdout.String(), "PrimeCloud Agent Daemon") {
				t.Error("stdout unexpectedly contains startup banner on version flag")
			}
		})
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"--invalid-flag"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run with invalid flag returned exit code %d, expected 2", exitCode)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should contain flag parsing error message")
	}
}

func TestRun_NonStartupOnVersionFlag(t *testing.T) {
	// Clear any primecloud environment variables to ensure config loading would fail
	// if run() improperly attempted to initialize the daemon.
	t.Setenv("PRIMECLOUD_AGENT_CONFIG_PATH", "/nonexistent/path/agent.env")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"--version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected clean exit (0) on --version even with invalid config path, got %d", exitCode)
	}
	if !strings.HasPrefix(stdout.String(), "primecloud-agent ") {
		t.Errorf("expected version prefix, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("expected zero stderr output, got %q", stderr.String())
	}
}

func TestSubprocess_LinkerInjectionAndExecution(t *testing.T) {
	// This test builds a temporary binary with ldflags and executes it as a real subprocess.
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "test-primecloud-agent")
	if os.Getenv("GOOS") == "windows" || filepath.Ext(os.Args[0]) == ".exe" {
		binPath += ".exe"
	}

	testTag := "v0.4.0-test"
	testCommit := "1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c"
	ldflags := "-s -w -X main.Version=" + testTag + " -X main.CommitSHA=" + testCommit

	buildCmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", binPath, ".")
	buildCmd.Dir = "."
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to compile test binary with ldflags: %v\nOutput:\n%s", err, string(buildOut))
	}

	// Test 1: --version
	cmdVersion := exec.Command(binPath, "--version")
	outVersion, err := cmdVersion.CombinedOutput()
	if err != nil {
		t.Fatalf("binary --version failed: %v\nOutput: %s", err, string(outVersion))
	}
	expected := "primecloud-agent v0.4.0-test (commit: 1ac48ec6e1b20f62bbefc9a6467fc965cbc4008c)"
	if !strings.Contains(strings.TrimSpace(string(outVersion)), expected) {
		t.Errorf("binary --version output = %q, expected to contain %q", string(outVersion), expected)
	}

	// Test 2: -v
	cmdShort := exec.Command(binPath, "-v")
	outShort, err := cmdShort.CombinedOutput()
	if err != nil {
		t.Fatalf("binary -v failed: %v\nOutput: %s", err, string(outShort))
	}
	if !strings.Contains(strings.TrimSpace(string(outShort)), expected) {
		t.Errorf("binary -v output = %q, expected to contain %q", string(outShort), expected)
	}
}
