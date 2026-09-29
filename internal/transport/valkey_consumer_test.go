package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/operations"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

func TestValkeyConsumer_FullFlow(t *testing.T) {
	// 1. Setup mock Valkey TCP Server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	resultChan := make(chan map[string]interface{}, 1)

	// Mock server loop
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		opEnqueued := false

		for {
			cmd, err := parseRESP(reader)
			if err != nil {
				return
			}
			cmdArr, ok := cmd.([]interface{})
			if !ok || len(cmdArr) == 0 {
				continue
			}

			cmdName := strings.ToUpper(fmt.Sprintf("%v", cmdArr[0]))

			if cmdName == "BLPOP" {
				if !opEnqueued {
					opEnqueued = true
					// Return fake operation envelope
					itemObj := map[string]interface{}{
						"id":    "op-valkey-test-001",
						"queue": "queue:node:0191c001-0000-7000-8000-000000000001:operations",
						"payload": map[string]interface{}{
							"operation_id":   "op-valkey-test-001",
							"operation_type": "test_op",
							"resource_id":    "res-123",
							"project_id":     "proj-123",
							"environment_id": "env-123",
							"payload_json":   `{"key":"val"}`,
						},
					}
					itemBytes, _ := json.Marshal(itemObj)
					itemStr := string(itemBytes)
					keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"

					resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
					writer.WriteString(resp)
					writer.Flush()
				} else {
					// Timeout reply (nil array)
					writer.WriteString("*-1\r\n")
					writer.Flush()
				}
			} else if cmdName == "SETEX" {
				if len(cmdArr) >= 4 {
					valStr := fmt.Sprintf("%v", cmdArr[3])
					var resMap map[string]interface{}
					_ = json.Unmarshal([]byte(valStr), &resMap)
					resultChan <- resMap
				}
				writer.WriteString("+OK\r\n")
				writer.Flush()
			}
		}
	}()

	// 2. Setup Dispatcher and registered handler
	registry := operations.NewRegistry()
	registry.Register("test_op", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      `{"container_id":"cnt-test-999","status":"RUNNING"}`,
			Message:         "Test handler executed successfully",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)

	// 3. Create and start ValkeyConsumer
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	// 4. Assert result stored in mock Valkey server
	select {
	case result := <-resultChan:
		if result["operation_id"] != "op-valkey-test-001" {
			t.Errorf("expected operation_id op-valkey-test-001, got %v", result["operation_id"])
		}
		if result["status"] != "SUCCEEDED" {
			t.Errorf("expected status SUCCEEDED, got %v", result["status"])
		}
		if result["success"] != true {
			t.Errorf("expected success true, got %v", result["success"])
		}
		data, ok := result["data"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected data dict in result, got %v", result["data"])
		}
		if data["container_id"] != "cnt-test-999" {
			t.Errorf("expected container_id cnt-test-999, got %v", data["container_id"])
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for ValkeyConsumer to process operation and store result")
	}
}
