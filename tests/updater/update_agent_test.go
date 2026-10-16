package updater_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func findBash(t *testing.T) string {
	if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
			"bash.exe",
		}
		for _, c := range candidates {
			cmd := exec.Command(c, "-c", "echo ok")
			if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) == "ok" {
				return c
			}
		}
	}
	path, err := exec.LookPath("bash")
	if err == nil {
		cmd := exec.Command(path, "-c", "echo ok")
		if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) == "ok" {
			return path
		}
	}
	t.Skip("bash not found or not working on this host")
	return ""
}

func TestUpdateAgentScript(t *testing.T) {
	bashPath := findBash(t)

	testScriptPath := filepath.Join("..", "test_update_agent.sh")
	absPath, err := filepath.Abs(testScriptPath)
	if err != nil {
		t.Fatalf("failed to resolve test script path: %v", err)
	}

	cmd := exec.Command(bashPath, absPath)
	cmd.Dir = filepath.Dir(absPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("test_update_agent.sh failed: %v\nOutput:\n%s", err, string(output))
	}
}
