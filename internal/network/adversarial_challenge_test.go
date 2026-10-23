package network_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/network"
)

// TestAdversarial_DNSAliasesFormatters stress-tests FormatMySQLAliases and
// FormatMongoDBAliases with boundary inputs, whitespace, special characters,
// and edge-case IDs.
func TestAdversarial_DNSAliasesFormatters(t *testing.T) {
	testCases := []struct {
		name          string
		inputID       string
		expectedMySQL []string
		expectedMongo []string
	}{
		{
			name:    "Standard UUIDv7",
			inputID: "018f3a8b-1234-7000-8000-000000000001",
			expectedMySQL: []string{
				"mysql-018f3a8b-1234-7000-8000-000000000001.internal.primecloud",
				"mysql-018f3a8b-1234-7000-8000-000000000001",
			},
			expectedMongo: []string{
				"mongodb-018f3a8b-1234-7000-8000-000000000001.internal.primecloud",
				"mongodb-018f3a8b-1234-7000-8000-000000000001",
			},
		},
		{
			name:    "Whitespace trimmed input",
			inputID: "   my-db-resource-100   ",
			expectedMySQL: []string{
				"mysql-my-db-resource-100.internal.primecloud",
				"mysql-my-db-resource-100",
			},
			expectedMongo: []string{
				"mongodb-my-db-resource-100.internal.primecloud",
				"mongodb-my-db-resource-100",
			},
		},
		{
			name:    "Short slug identifier",
			inputID: "prod-db",
			expectedMySQL: []string{
				"mysql-prod-db.internal.primecloud",
				"mysql-prod-db",
			},
			expectedMongo: []string{
				"mongodb-prod-db.internal.primecloud",
				"mongodb-prod-db",
			},
		},
		{
			name:    "Empty input string",
			inputID: "",
			expectedMySQL: []string{
				"mysql-.internal.primecloud",
				"mysql-",
			},
			expectedMongo: []string{
				"mongodb-.internal.primecloud",
				"mongodb-",
			},
		},
		{
			name:    "All whitespace input string",
			inputID: "    \t \n  ",
			expectedMySQL: []string{
				"mysql-.internal.primecloud",
				"mysql-",
			},
			expectedMongo: []string{
				"mongodb-.internal.primecloud",
				"mongodb-",
			},
		},
		{
			name:    "Dotted resource identifier",
			inputID: "tenant.db.node1",
			expectedMySQL: []string{
				"mysql-tenant.db.node1.internal.primecloud",
				"mysql-tenant.db.node1",
			},
			expectedMongo: []string{
				"mongodb-tenant.db.node1.internal.primecloud",
				"mongodb-tenant.db.node1",
			},
		},
	}

	for _, tc := range testCases {
		t.Run("MySQL_"+tc.name, func(t *testing.T) {
			aliases := network.FormatMySQLAliases(tc.inputID)
			if len(aliases) != len(tc.expectedMySQL) {
				t.Fatalf("expected %d aliases, got %d: %v", len(tc.expectedMySQL), len(aliases), aliases)
			}
			for i := range aliases {
				if aliases[i] != tc.expectedMySQL[i] {
					t.Fatalf("alias mismatch at [%d]: expected %q, got %q", i, tc.expectedMySQL[i], aliases[i])
				}
			}
		})

		t.Run("Mongo_"+tc.name, func(t *testing.T) {
			aliases := network.FormatMongoDBAliases(tc.inputID)
			if len(aliases) != len(tc.expectedMongo) {
				t.Fatalf("expected %d aliases, got %d: %v", len(tc.expectedMongo), len(aliases), aliases)
			}
			for i := range aliases {
				if aliases[i] != tc.expectedMongo[i] {
					t.Fatalf("alias mismatch at [%d]: expected %q, got %q", i, tc.expectedMongo[i], aliases[i])
				}
			}
		})
	}
}

// TestAdversarial_DNSAliasesAttachment verifies that formatted aliases attach
// to environment bridge networks cleanly through Manager.AttachContainerToEnvironmentNetwork.
func TestAdversarial_DNSAliasesAttachment(t *testing.T) {
	mockCli := newMockDockerClient()
	mgr := network.NewManager(mockCli, "node-adv-001", nil)
	ctx := context.Background()
	envID := "env-adv-test"

	mysqlID := "018f3a8b-mysql-0001"
	mongoID := "018f3a8b-mongo-0002"

	mysqlAliases := network.FormatMySQLAliases(mysqlID)
	mongoAliases := network.FormatMongoDBAliases(mongoID)

	err := mgr.AttachContainerToEnvironmentNetwork(ctx, envID, "pc-mysql-container", mysqlAliases)
	if err != nil {
		t.Fatalf("failed to attach mysql container: %v", err)
	}

	err = mgr.AttachContainerToEnvironmentNetwork(ctx, envID, "pc-mongo-container", mongoAliases)
	if err != nil {
		t.Fatalf("failed to attach mongo container: %v", err)
	}

	info, err := mgr.InspectEnvironmentNetwork(ctx, envID)
	if err != nil {
		t.Fatalf("failed to inspect network: %v", err)
	}
	if info.Name != fmt.Sprintf("pc-net-%s", envID) {
		t.Fatalf("unexpected network name: %s", info.Name)
	}
}
