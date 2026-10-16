package updater_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func loadDeployWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", "deploy.yml")
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to resolve deploy.yml path: %v", err)
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatalf("failed to read deploy.yml at %s: %v", absPath, err)
	}

	return string(content)
}

func TestDeployWorkflow_TriggerSecurity(t *testing.T) {
	content := loadDeployWorkflow(t)

	// 1. Must trigger on published releases
	if !strings.Contains(content, "release:") || !strings.Contains(content, "types: [published]") {
		t.Error("deploy.yml must trigger on release: types: [published]")
	}

	// 2. Must trigger on workflow_dispatch with required tag
	if !strings.Contains(content, "workflow_dispatch:") {
		t.Error("deploy.yml must support manual workflow_dispatch")
	}
	if !strings.Contains(content, "tag:") || !strings.Contains(content, "required: true") {
		t.Error("deploy.yml workflow_dispatch must require a 'tag' input")
	}

	// 3. Must support dry_run input
	if !strings.Contains(content, "dry_run:") {
		t.Error("deploy.yml workflow_dispatch should support 'dry_run' boolean option")
	}

	// 4. Must NEVER trigger on pull_request or push to arbitrary branches
	if strings.Contains(content, "pull_request:") {
		t.Error("deploy.yml must NEVER trigger on pull_request (security violation)")
	}
	if strings.Contains(content, "push:") {
		t.Error("deploy.yml must NEVER trigger on push to arbitrary branches (security violation)")
	}
}

func TestDeployWorkflow_EnvironmentAndConcurrency(t *testing.T) {
	content := loadDeployWorkflow(t)

	// 1. Must use 'production' environment
	envRegex := regexp.MustCompile(`environment:\s*\n\s*name:\s*production`)
	if !envRegex.MatchString(content) {
		t.Error("deploy.yml must be bound to the 'production' environment")
	}

	// 2. Must serialize deployments with concurrency group
	if !strings.Contains(content, "concurrency:") {
		t.Error("deploy.yml must define concurrency")
	}
	if !strings.Contains(content, "group: production-deployment-pc-node-001-agent") {
		t.Error("deploy.yml must lock concurrency group 'production-deployment-pc-node-001-agent'")
	}
	if !strings.Contains(content, "cancel-in-progress: false") {
		t.Error("deploy.yml must set cancel-in-progress: false to prevent mid-deploy cancellations")
	}
}

func TestDeployWorkflow_LeastPrivilegePermissions(t *testing.T) {
	content := loadDeployWorkflow(t)

	permRegex := regexp.MustCompile(`permissions:\s*\n\s*contents:\s*read`)
	if !permRegex.MatchString(content) {
		t.Error("deploy.yml must restrict permissions to 'contents: read'")
	}

	// Verify no write permissions
	forbiddenPerms := []string{
		"contents: write",
		"packages: write",
		"actions: write",
		"id-token: write",
		"security-events: write",
	}
	for _, p := range forbiddenPerms {
		if strings.Contains(content, p) {
			t.Errorf("deploy.yml unexpectedly grants elevated permission: %q", p)
		}
	}
}

func TestDeployWorkflow_TagAndChecksumValidation(t *testing.T) {
	content := loadDeployWorkflow(t)

	// 1. Tag format regex
	if !strings.Contains(content, `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`) {
		t.Error("deploy.yml must validate release tag with strict SemVer regex")
	}

	// 2. Checksum format regex (64 hex characters)
	if !strings.Contains(content, `^[0-9a-f]{64}$`) && !strings.Contains(content, `^[0-9a-fA-F]{64}$`) {
		t.Error("deploy.yml must validate checksum with 64-character hex regex")
	}

	// 3. Asset target
	if !strings.Contains(content, "primecloud-agent-linux-amd64.tar.gz") {
		t.Error("deploy.yml must target the linux-amd64 asset for pc-node-001")
	}
}

func TestDeployWorkflow_SSHSecurityInvariants(t *testing.T) {
	content := loadDeployWorkflow(t)

	// 1. StrictHostKeyChecking must be yes
	if !strings.Contains(content, "-o StrictHostKeyChecking=yes") {
		t.Error("deploy.yml must enforce StrictHostKeyChecking=yes")
	}
	if strings.Contains(content, "StrictHostKeyChecking=no") {
		t.Error("deploy.yml must NEVER disable host key checking (StrictHostKeyChecking=no found!)")
	}

	// 2. Verified host key check
	if !strings.Contains(content, "ssh-keygen -F") {
		t.Error("deploy.yml must verify host key using ssh-keygen -F against known_hosts")
	}

	// 3. UserKnownHostsFile specified
	if !strings.Contains(content, "-o UserKnownHostsFile=~/.ssh/known_hosts") {
		t.Error("deploy.yml must explicitly specify UserKnownHostsFile")
	}

	// 4. BatchMode and IdentitiesOnly
	if !strings.Contains(content, "-o BatchMode=yes") {
		t.Error("deploy.yml must use BatchMode=yes for non-interactive execution")
	}
	if !strings.Contains(content, "-o IdentitiesOnly=yes") {
		t.Error("deploy.yml must use IdentitiesOnly=yes")
	}

	// 5. Hardened wrapper invocation
	if !strings.Contains(content, "sudo -n /opt/primecloud-bootstrap/agent_deploy_wrapper.sh") {
		t.Error("deploy.yml must delegate to /opt/primecloud-bootstrap/agent_deploy_wrapper.sh via sudo -n")
	}

	// 6. Must not invoke raw bash or arbitrary commands via sudo
	if strings.Contains(content, "sudo bash") || strings.Contains(content, "sudo sh") {
		t.Error("deploy.yml must never invoke raw sudo bash/sh")
	}
}

func TestDeployWorkflow_AuditSummary(t *testing.T) {
	content := loadDeployWorkflow(t)

	if !strings.Contains(content, "GITHUB_STEP_SUMMARY") {
		t.Error("deploy.yml should write deployment audit summary to GITHUB_STEP_SUMMARY")
	}

	// Ensure no secrets are leaked in summary
	secretNames := []string{
		"${{ secrets.PROD_SSH_KEY }}",
		"${{ secrets.PROD_HOST }}",
		"${{ secrets.PROD_KNOWN_HOSTS }}",
	}
	for _, s := range secretNames {
		if strings.Contains(content, "echo \""+s) || strings.Contains(content, "echo '"+s) {
			t.Errorf("deploy.yml potentially leaks secret %s in echo command", s)
		}
	}
}
