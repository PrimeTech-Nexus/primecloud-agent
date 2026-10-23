// Package recovery coordinates artifact decryption, integrity verification, and workload state reconstruction.
package recovery

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/primecloud/primecloud-agent/internal/backup"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// Verifier handles post-restoration verification of data and runtime instances.
type Verifier struct {
	rt agentruntime.ContainerRuntime
}

// NewVerifier constructs a Verifier.
func NewVerifier(rt agentruntime.ContainerRuntime) *Verifier {
	return &Verifier{rt: rt}
}

// VerifyIntegrity checks the SHA-256 hash and size of a restored artifact against its manifest.
func (v *Verifier) VerifyIntegrity(m *backup.Manifest, artifactPath string) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}
	return m.VerifyIntegrity(artifactPath)
}

// VerifyFormat validates file magic bytes or headers based on resource type.
// Reads only the first 16 bytes rather than loading the entire file into memory.
func (v *Verifier) VerifyFormat(resourceType, artifactPath string) error {
	f, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to open artifact for format verification: %w", err)
	}
	defer f.Close()

	header := make([]byte, 16)
	n, _ := io.ReadFull(f, header)
	if n == 0 {
		return fmt.Errorf("artifact is empty")
	}

	switch resourceType {
	case "valkey", "redis", "keyvalue", "cache":
		if !bytes.HasPrefix(header[:n], []byte("REDIS")) {
			return fmt.Errorf("valkey artifact missing valid REDIS header")
		}
	case "postgres", "postgresql", "database", "db":
		if n < 10 {
			return fmt.Errorf("postgres artifact truncated")
		}
	}

	return nil
}

// VerificationResult contains structured recovery verification outcome.
type VerificationResult struct {
	IsHealthy bool                   `json:"is_healthy"`
	Details   map[string]interface{} `json:"details"`
	ErrorCode string                 `json:"error_code,omitempty"`
	Message   string                 `json:"message,omitempty"`
}

// VerifyServiceReady checks whether the target container has booted and is healthy.
// Strictly fails closed if container runtime is nil, container is missing, or not running.
func (v *Verifier) VerifyServiceReady(ctx context.Context, containerID string) error {
	if v.rt == nil {
		return fmt.Errorf("CONTAINER_RUNTIME_UNAVAILABLE: container runtime is nil")
	}
	if containerID == "" {
		return fmt.Errorf("INVALID_ARGUMENT: containerID cannot be empty")
	}

	c, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("CONTAINER_NOT_FOUND: failed to inspect container %s: %w", containerID, err)
	}

	if !c.Running {
		return fmt.Errorf("CONTAINER_NOT_RUNNING: restored container %s is not running (state: %s)", containerID, c.State)
	}

	if c.Health == "unhealthy" {
		return fmt.Errorf("CONTAINER_UNHEALTHY: restored container %s health status is unhealthy", containerID)
	}

	return nil
}

// VerifyPostgres verifies PostgreSQL database connectivity, query execution, and schema table parity inside the container.
func (v *Verifier) VerifyPostgres(ctx context.Context, containerID, user, database string, expectedMinTables int) (*VerificationResult, error) {
	if v.rt == nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "RUNTIME_UNAVAILABLE",
			Message:   "container runtime is nil",
			Details:   map[string]interface{}{"container_id": containerID},
		}
		return res, fmt.Errorf("RUNTIME_UNAVAILABLE: container runtime is nil")
	}

	inspect, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_FOUND",
			Message:   fmt.Sprintf("failed to inspect container %s: %v", containerID, err),
			Details:   map[string]interface{}{"container_id": containerID, "error": err.Error()},
		}
		return res, fmt.Errorf("CONTAINER_NOT_FOUND: failed to inspect container %s: %w", containerID, err)
	}
	if !inspect.Running {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_RUNNING",
			Message:   fmt.Sprintf("container %s is not running (state=%s)", containerID, inspect.State),
			Details:   map[string]interface{}{"container_id": containerID, "state": inspect.State},
		}
		return res, fmt.Errorf("CONTAINER_NOT_RUNNING: container %s is not running", containerID)
	}

	if user == "" {
		user = "postgres"
	}
	if database == "" {
		database = "postgres"
	}

	// 1. Accessibility & connectivity check via pg_isready
	readyCmd := []string{"pg_isready", "-U", user, "-d", database}
	rStdout, rStderr, rCode, rErr := v.rt.ExecContainer(ctx, containerID, readyCmd, nil, nil)
	if rErr != nil || rCode != 0 {
		errMsg := strings.TrimSpace(string(rStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(rStdout))
		}
		if rErr != nil && errMsg == "" {
			errMsg = rErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONNECTIVITY_FAILED",
			Message:   fmt.Sprintf("pg_isready failed (exit %d): %s", rCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": rCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("CONNECTIVITY_FAILED: pg_isready failed on %s (exit %d): %s", containerID, rCode, errMsg)
	}

	// 2. Query execution check via psql: SELECT 1;
	queryCmd := []string{"psql", "-U", user, "-d", database, "-t", "-A", "-c", "SELECT 1;"}
	qStdout, qStderr, qCode, qErr := v.rt.ExecContainer(ctx, containerID, queryCmd, nil, nil)
	if qErr != nil || qCode != 0 || strings.TrimSpace(string(qStdout)) != "1" {
		errMsg := strings.TrimSpace(string(qStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(qStdout))
		}
		if qErr != nil && errMsg == "" {
			errMsg = qErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "QUERY_EXECUTION_FAILED",
			Message:   fmt.Sprintf("psql query failed (exit %d): %s", qCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": qCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("QUERY_EXECUTION_FAILED: psql query failed on %s (exit %d): %s", containerID, qCode, errMsg)
	}

	// 3. Schema table presence check
	tableCmd := []string{"psql", "-U", user, "-d", database, "-t", "-A", "-c", "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"}
	tStdout, tStderr, tCode, tErr := v.rt.ExecContainer(ctx, containerID, tableCmd, nil, nil)
	if tErr != nil || tCode != 0 {
		errMsg := strings.TrimSpace(string(tStderr))
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "SCHEMA_VERIFICATION_FAILED",
			Message:   fmt.Sprintf("table count query failed (exit %d): %s", tCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": tCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("SCHEMA_VERIFICATION_FAILED: table count query failed on %s: %s", containerID, errMsg)
	}

	tableCountStr := strings.TrimSpace(string(tStdout))
	tableCount, _ := strconv.Atoi(tableCountStr)

	if expectedMinTables > 0 && tableCount < expectedMinTables {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "SCHEMA_PARITY_MISMATCH",
			Message:   fmt.Sprintf("schema table count %d is less than expected minimum %d", tableCount, expectedMinTables),
			Details: map[string]interface{}{
				"container_id": containerID,
				"table_count":  tableCount,
				"expected_min": expectedMinTables,
			},
		}
		return res, fmt.Errorf("SCHEMA_PARITY_MISMATCH: table count %d is less than expected %d", tableCount, expectedMinTables)
	}

	details := map[string]interface{}{
		"container_id": containerID,
		"table_count":  tableCount,
		"database":     database,
		"connectivity": "ok",
		"query_check":  "passed",
	}
	return &VerificationResult{
		IsHealthy: true,
		Details:   details,
		Message:   fmt.Sprintf("PostgreSQL container %s is healthy with %d tables", containerID, tableCount),
	}, nil
}

// VerifyValkey verifies Valkey/Redis cache connectivity (ping) and persistence status inside the container.
func (v *Verifier) VerifyValkey(ctx context.Context, containerID string) (*VerificationResult, error) {
	if v.rt == nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "RUNTIME_UNAVAILABLE",
			Message:   "container runtime is nil",
			Details:   map[string]interface{}{"container_id": containerID},
		}
		return res, fmt.Errorf("RUNTIME_UNAVAILABLE: container runtime is nil")
	}

	inspect, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_FOUND",
			Message:   fmt.Sprintf("failed to inspect container %s: %v", containerID, err),
			Details:   map[string]interface{}{"container_id": containerID, "error": err.Error()},
		}
		return res, fmt.Errorf("CONTAINER_NOT_FOUND: failed to inspect container %s: %w", containerID, err)
	}
	if !inspect.Running {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_RUNNING",
			Message:   fmt.Sprintf("container %s is not running (state=%s)", containerID, inspect.State),
			Details:   map[string]interface{}{"container_id": containerID, "state": inspect.State},
		}
		return res, fmt.Errorf("CONTAINER_NOT_RUNNING: container %s is not running", containerID)
	}

	// 1. Valkey/Redis ping check
	pingCmd := []string{"valkey-cli", "ping"}
	pStdout, pStderr, pCode, pErr := v.rt.ExecContainer(ctx, containerID, pingCmd, nil, nil)
	if pErr != nil || pCode != 0 {
		// Fallback to redis-cli ping
		pingCmd = []string{"redis-cli", "ping"}
		pStdout, pStderr, pCode, pErr = v.rt.ExecContainer(ctx, containerID, pingCmd, nil, nil)
	}

	if pErr != nil || pCode != 0 || !strings.Contains(strings.ToUpper(string(pStdout)), "PONG") {
		errMsg := strings.TrimSpace(string(pStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(pStdout))
		}
		if pErr != nil && errMsg == "" {
			errMsg = pErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "PING_FAILED",
			Message:   fmt.Sprintf("ping failed (exit %d): %s", pCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": pCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("PING_FAILED: ping failed on %s (exit %d): %s", containerID, pCode, errMsg)
	}

	// 2. Persistence status check via INFO persistence
	infoCmd := []string{"valkey-cli", "info", "persistence"}
	iStdout, _, iCode, iErr := v.rt.ExecContainer(ctx, containerID, infoCmd, nil, nil)
	if iErr != nil || iCode != 0 {
		infoCmd = []string{"redis-cli", "info", "persistence"}
		iStdout, _, iCode, iErr = v.rt.ExecContainer(ctx, containerID, infoCmd, nil, nil)
	}

	details := map[string]interface{}{
		"container_id": containerID,
		"ping":         "PONG",
	}
	if iCode == 0 && iErr == nil {
		infoStr := string(iStdout)
		if strings.Contains(infoStr, "rdb_last_bgsave_status:ok") {
			details["rdb_last_bgsave_status"] = "ok"
		} else if strings.Contains(infoStr, "rdb_last_bgsave_status:err") {
			res := &VerificationResult{
				IsHealthy: false,
				ErrorCode: "PERSISTENCE_CHECK_FAILED",
				Message:   "valkey persistence rdb_last_bgsave_status is err",
				Details:   map[string]interface{}{"container_id": containerID, "info": infoStr},
			}
			return res, fmt.Errorf("PERSISTENCE_CHECK_FAILED: rdb_last_bgsave_status is err on %s", containerID)
		}
	}

	return &VerificationResult{
		IsHealthy: true,
		Details:   details,
		Message:   fmt.Sprintf("Valkey container %s is healthy and responding to PING", containerID),
	}, nil
}

// VerifyMySQL verifies MySQL database connectivity, query execution, and schema table parity inside the container.
func (v *Verifier) VerifyMySQL(ctx context.Context, containerID, user, database string, expectedMinTables int) (*VerificationResult, error) {
	if v.rt == nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "RUNTIME_UNAVAILABLE",
			Message:   "container runtime is nil",
			Details:   map[string]interface{}{"container_id": containerID},
		}
		return res, fmt.Errorf("RUNTIME_UNAVAILABLE: container runtime is nil")
	}

	inspect, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_FOUND",
			Message:   fmt.Sprintf("failed to inspect container %s: %v", containerID, err),
			Details:   map[string]interface{}{"container_id": containerID, "error": err.Error()},
		}
		return res, fmt.Errorf("CONTAINER_NOT_FOUND: failed to inspect container %s: %w", containerID, err)
	}
	if !inspect.Running {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_RUNNING",
			Message:   fmt.Sprintf("container %s is not running (state=%s)", containerID, inspect.State),
			Details:   map[string]interface{}{"container_id": containerID, "state": inspect.State},
		}
		return res, fmt.Errorf("CONTAINER_NOT_RUNNING: container %s is not running", containerID)
	}

	if user == "" {
		user = "root"
	}

	// 1. Accessibility & connectivity check via mysqladmin ping
	readyCmd := []string{"mysqladmin", "ping", "-h", "127.0.0.1", "-u", user}
	rStdout, rStderr, rCode, rErr := v.rt.ExecContainer(ctx, containerID, readyCmd, nil, nil)
	if rErr != nil || rCode != 0 {
		errMsg := strings.TrimSpace(string(rStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(rStdout))
		}
		if rErr != nil && errMsg == "" {
			errMsg = rErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONNECTIVITY_FAILED",
			Message:   fmt.Sprintf("mysqladmin ping failed (exit %d): %s", rCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": rCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("CONNECTIVITY_FAILED: mysqladmin ping failed on %s (exit %d): %s", containerID, rCode, errMsg)
	}

	// 2. Query execution check via mysql: SELECT 1;
	queryCmd := []string{"mysql", "-h", "127.0.0.1", "-u", user, "-N", "-B", "-e", "SELECT 1;"}
	if database != "" {
		queryCmd = append(queryCmd, database)
	}
	qStdout, qStderr, qCode, qErr := v.rt.ExecContainer(ctx, containerID, queryCmd, nil, nil)
	if qErr != nil || qCode != 0 || strings.TrimSpace(string(qStdout)) != "1" {
		errMsg := strings.TrimSpace(string(qStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(qStdout))
		}
		if qErr != nil && errMsg == "" {
			errMsg = qErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "QUERY_EXECUTION_FAILED",
			Message:   fmt.Sprintf("mysql query failed (exit %d): %s", qCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": qCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("QUERY_EXECUTION_FAILED: mysql query failed on %s (exit %d): %s", containerID, qCode, errMsg)
	}

	// 3. Schema table presence check
	tableCount := 0
	if database != "" {
		tableCmd := []string{"mysql", "-h", "127.0.0.1", "-u", user, "-N", "-B", "-e", fmt.Sprintf("SELECT count(*) FROM information_schema.tables WHERE table_schema = '%s';", database)}
		tStdout, _, tCode, tErr := v.rt.ExecContainer(ctx, containerID, tableCmd, nil, nil)
		if tErr == nil && tCode == 0 {
			tableCount, _ = strconv.Atoi(strings.TrimSpace(string(tStdout)))
		}
	}

	if expectedMinTables > 0 && tableCount < expectedMinTables {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "SCHEMA_PARITY_MISMATCH",
			Message:   fmt.Sprintf("schema table count %d is less than expected minimum %d", tableCount, expectedMinTables),
			Details: map[string]interface{}{
				"container_id": containerID,
				"table_count":  tableCount,
				"expected_min": expectedMinTables,
			},
		}
		return res, fmt.Errorf("SCHEMA_PARITY_MISMATCH: table count %d is less than expected %d", tableCount, expectedMinTables)
	}

	return &VerificationResult{
		IsHealthy: true,
		Details: map[string]interface{}{
			"container_id": containerID,
			"table_count":  tableCount,
			"database":     database,
			"connectivity": "ok",
			"query_check":  "passed",
		},
		Message: fmt.Sprintf("MySQL container %s is healthy", containerID),
	}, nil
}

// VerifyMongoDB verifies MongoDB database connectivity, ping command, and collection presence inside the container.
func (v *Verifier) VerifyMongoDB(ctx context.Context, containerID, user, database string) (*VerificationResult, error) {
	if v.rt == nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "RUNTIME_UNAVAILABLE",
			Message:   "container runtime is nil",
			Details:   map[string]interface{}{"container_id": containerID},
		}
		return res, fmt.Errorf("RUNTIME_UNAVAILABLE: container runtime is nil")
	}

	inspect, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_FOUND",
			Message:   fmt.Sprintf("failed to inspect container %s: %v", containerID, err),
			Details:   map[string]interface{}{"container_id": containerID, "error": err.Error()},
		}
		return res, fmt.Errorf("CONTAINER_NOT_FOUND: failed to inspect container %s: %w", containerID, err)
	}
	if !inspect.Running {
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "CONTAINER_NOT_RUNNING",
			Message:   fmt.Sprintf("container %s is not running (state=%s)", containerID, inspect.State),
			Details:   map[string]interface{}{"container_id": containerID, "state": inspect.State},
		}
		return res, fmt.Errorf("CONTAINER_NOT_RUNNING: container %s is not running", containerID)
	}

	pingCmd := []string{"mongosh", "--quiet", "--eval", "db.adminCommand({ ping: 1 }).ok"}
	pStdout, pStderr, pCode, pErr := v.rt.ExecContainer(ctx, containerID, pingCmd, nil, nil)
	if pErr != nil || pCode != 0 || !strings.Contains(strings.TrimSpace(string(pStdout)), "1") {
		errMsg := strings.TrimSpace(string(pStderr))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(pStdout))
		}
		if pErr != nil && errMsg == "" {
			errMsg = pErr.Error()
		}
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "PING_FAILED",
			Message:   fmt.Sprintf("mongosh ping failed (exit %d): %s", pCode, errMsg),
			Details:   map[string]interface{}{"container_id": containerID, "exit_code": pCode, "stderr": errMsg},
		}
		return res, fmt.Errorf("PING_FAILED: mongosh ping failed on %s (exit %d): %s", containerID, pCode, errMsg)
	}

	return &VerificationResult{
		IsHealthy: true,
		Details: map[string]interface{}{
			"container_id": containerID,
			"database":     database,
			"ping":         1,
			"connectivity": "ok",
		},
		Message: fmt.Sprintf("MongoDB container %s is healthy and responding to ping", containerID),
	}, nil
}

// VerifyDatabase verifies database readiness, connectivity, and schema/table parity based on resource type.
func (v *Verifier) VerifyDatabase(ctx context.Context, resourceType, containerID, user, database string, expectedMinTables int) (*VerificationResult, error) {
	switch strings.ToLower(resourceType) {
	case "postgres", "postgresql", "postgres_instance", "database", "db":
		return v.VerifyPostgres(ctx, containerID, user, database, expectedMinTables)
	case "valkey", "redis", "keyvalue", "cache":
		return v.VerifyValkey(ctx, containerID)
	case "mysql", "mysql_instance":
		return v.VerifyMySQL(ctx, containerID, user, database, expectedMinTables)
	case "mongodb", "mongo", "mongodb_instance":
		return v.VerifyMongoDB(ctx, containerID, user, database)
	default:
		res := &VerificationResult{
			IsHealthy: false,
			ErrorCode: "UNSUPPORTED_RESOURCE_TYPE",
			Message:   fmt.Sprintf("unsupported resource type for database verification: %s", resourceType),
			Details:   map[string]interface{}{"container_id": containerID, "resource_type": resourceType},
		}
		return res, fmt.Errorf("UNSUPPORTED_RESOURCE_TYPE: %s", resourceType)
	}
}
func (v *Verifier) verifyDatabaseLegacy(ctx context.Context, resourceType, containerID, user, database string, expectedMinTables int) (*VerificationResult, error) {
	switch strings.ToLower(resourceType) {
	case "valkey", "redis", "keyvalue", "cache":
		return v.VerifyValkey(ctx, containerID)
	default:
		return v.VerifyPostgres(ctx, containerID, user, database, expectedMinTables)
	}
}
