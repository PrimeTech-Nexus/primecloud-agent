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
	"sync"
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
	var opMu sync.Mutex
	opEnqueued := false

	// Mock server loop accepting connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)
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
						opMu.Lock()
						shouldEnqueue := !opEnqueued
						if shouldEnqueue {
							opEnqueued = true
						}
						opMu.Unlock()

						if shouldEnqueue {
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
			}(conn)
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

func TestValkeyConsumer_ReadErrorReconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	resultChan := make(chan string, 1)
	connCount := 0

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connCount++
			currentConnIndex := connCount

			go func(c net.Conn, idx int) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)

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
						if idx == 1 {
							// Simulate sudden connection failure / reset on first connection
							c.Close()
							return
						}
						// On second connection, return valid operation
						itemObj := map[string]interface{}{
							"id": "op-reconnect-001",
							"payload": map[string]interface{}{
								"operation_id":   "op-reconnect-001",
								"operation_type": "reconnect_test",
								"application_id": "app-reconnect-123",
							},
						}
						itemBytes, _ := json.Marshal(itemObj)
						itemStr := string(itemBytes)
						keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"
						resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
						writer.WriteString(resp)
						writer.Flush()
					} else if cmdName == "SETEX" {
						resultChan <- "reconnected_and_published"
						writer.WriteString("+OK\r\n")
						writer.Flush()
					}
				}
			}(conn, currentConnIndex)
		}
	}()

	registry := operations.NewRegistry()
	registry.Register("reconnect_test", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	select {
	case res := <-resultChan:
		if res != "reconnected_and_published" {
			t.Errorf("unexpected result: %v", res)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for consumer to reconnect and process operation")
	}
}

func TestValkeyConsumer_ParseErrorReconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	resultChan := make(chan string, 1)
	connCount := 0

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connCount++
			currentConnIndex := connCount

			go func(c net.Conn, idx int) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)

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
						if idx == 1 {
							// Return corrupted RESP frame with invalid prefix to trigger parse error
							writer.WriteString("!GARBAGE_RESP_PREFIX\r\n")
							writer.Flush()
							return
						}
						// On second connection, return valid operation
						itemObj := map[string]interface{}{
							"id": "op-parse-err-001",
							"payload": map[string]interface{}{
								"operation_id":   "op-parse-err-001",
								"operation_type": "parse_test",
								"application_id": "app-parse-123",
							},
						}
						itemBytes, _ := json.Marshal(itemObj)
						itemStr := string(itemBytes)
						keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"
						resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
						writer.WriteString(resp)
						writer.Flush()
					} else if cmdName == "SETEX" {
						resultChan <- "recovered_after_parse_error"
						writer.WriteString("+OK\r\n")
						writer.Flush()
					}
				}
			}(conn, currentConnIndex)
		}
	}()

	registry := operations.NewRegistry()
	registry.Register("parse_test", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	select {
	case res := <-resultChan:
		if res != "recovered_after_parse_error" {
			t.Errorf("unexpected result: %v", res)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for consumer to reset on parse error and recover")
	}
}

func TestValkeyConsumer_EnvelopeFallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	receivedEnvelopeChan := make(chan *pb.OperationEnvelope, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)
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
						// Payload with application_id and NO resource_id
						itemObj := map[string]interface{}{
							"id": "op-fallback-001",
							"payload": map[string]interface{}{
								"operation_id":   "op-fallback-001",
								"operation_type": "fallback_test",
								"application_id": "app-fallback-uuid",
								"project_id":     "proj-fallback-uuid",
								"parameters": map[string]interface{}{
									"environment_id": "env-fallback-uuid",
								},
							},
						}
						itemBytes, _ := json.Marshal(itemObj)
						itemStr := string(itemBytes)
						keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"
						resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
						writer.WriteString(resp)
						writer.Flush()
					} else if cmdName == "SETEX" {
						writer.WriteString("+OK\r\n")
						writer.Flush()
					}
				}
			}(conn)
		}
	}()

	registry := operations.NewRegistry()
	registry.Register("fallback_test", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		receivedEnvelopeChan <- op
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	select {
	case env := <-receivedEnvelopeChan:
		if env.ResourceId != "app-fallback-uuid" {
			t.Errorf("expected ResourceId to fall back to application_id 'app-fallback-uuid', got '%s'", env.ResourceId)
		}
		if env.ProjectId != "proj-fallback-uuid" {
			t.Errorf("expected ProjectId 'proj-fallback-uuid', got '%s'", env.ProjectId)
		}
		if env.EnvironmentId != "env-fallback-uuid" {
			t.Errorf("expected EnvironmentId 'env-fallback-uuid', got '%s'", env.EnvironmentId)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for envelope fallback test")
	}
}

func TestValkeyConsumer_TopLevelIdentityWithNestedPayload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	receivedEnvelopeChan := make(chan *pb.OperationEnvelope, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)
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
						// Authentic Control Plane AgentOperationPayload schema
						itemObj := map[string]interface{}{
							"operation_id":   "ebaa013b-007f-43a4-96ea-b2ea541703a8",
							"operation_type": "deploy_application",
							"node_id":        "0191c001-0000-7000-8000-000000000001",
							"resource_id":    "01a0ea25-2887-7cf2-9bcd-2a7a18850df3",
							"application_id": "01a0ea25-2887-7cf2-9bcd-2a7a18850df3",
							"project_id":     "0191proj-0000-7000-8000-000000000001",
							"environment_id": "0191env0-0000-7000-8000-000000000001",
							"deployment_id":  "01a0f29f-1c84-7c25-8c43-ab9bb78edfc6",
							"payload": map[string]interface{}{
								"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
								"env": map[string]interface{}{
									"PORT": "8080",
								},
								"secret_refs": map[string]interface{}{
									"SECRET_KEY": "secret/data/primecloud/tenants/proj/app/env#SECRET_KEY",
								},
							},
							"parameters": map[string]interface{}{
								"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
								"port":  8080,
							},
						}
						itemBytes, _ := json.Marshal(itemObj)
						itemStr := string(itemBytes)
						keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"
						resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
						writer.WriteString(resp)
						writer.Flush()
					} else if cmdName == "SETEX" {
						writer.WriteString("+OK\r\n")
						writer.Flush()
					}
				}
			}(conn)
		}
	}()

	registry := operations.NewRegistry()
	registry.Register("deploy_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		receivedEnvelopeChan <- op
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	select {
	case env := <-receivedEnvelopeChan:
		if env.OperationId != "ebaa013b-007f-43a4-96ea-b2ea541703a8" {
			t.Errorf("expected OperationId 'ebaa013b-007f-43a4-96ea-b2ea541703a8', got '%s'", env.OperationId)
		}
		if env.OperationType != "deploy_application" {
			t.Errorf("expected OperationType 'deploy_application', got '%s'", env.OperationType)
		}
		if env.ResourceId != "01a0ea25-2887-7cf2-9bcd-2a7a18850df3" {
			t.Errorf("expected ResourceId '01a0ea25-2887-7cf2-9bcd-2a7a18850df3', got '%s'", env.ResourceId)
		}
		if env.ProjectId != "0191proj-0000-7000-8000-000000000001" {
			t.Errorf("expected ProjectId '0191proj-0000-7000-8000-000000000001', got '%s'", env.ProjectId)
		}
		if env.EnvironmentId != "0191env0-0000-7000-8000-000000000001" {
			t.Errorf("expected EnvironmentId '0191env0-0000-7000-8000-000000000001', got '%s'", env.EnvironmentId)
		}

		var payloadMap map[string]interface{}
		if err := json.Unmarshal([]byte(env.PayloadJson), &payloadMap); err != nil {
			t.Fatalf("failed to unmarshal payload JSON: %v", err)
		}
		if payloadMap["project_id"] != "0191proj-0000-7000-8000-000000000001" {
			t.Errorf("expected payload project_id to be preserved, got '%v'", payloadMap["project_id"])
		}
		if payloadMap["image"] != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
			t.Errorf("expected payload image to be preserved, got '%v'", payloadMap["image"])
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for top-level identity test")
	}
}

func TestValkeyConsumer_RealQueueEnvelopePreservesExternalPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	receivedEnvelopeChan := make(chan *pb.OperationEnvelope, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)
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
						// Authentic Control Plane queue item produced by QueueClient.enqueue:
						// {"id": "<job_id>", "queue": "node:<id>:operations", "payload": {<envelope>}}
						// where envelope contains "payload_json" as a serialized string containing external_port: 30001
						innerPayloadJSON, _ := json.Marshal(map[string]interface{}{
							"postgres_id":   "01a114c4-b0df-7ef2-a680-8fef961e8daa",
							"resource_id":   "01a114c4-b0df-7ef2-a680-8fef961e8daa",
							"external_port": 30001,
							"port":          30001,
							"node_id":       "0191c001-0000-7000-8000-000000000001",
						})
						itemObj := map[string]interface{}{
							"id":    "job-enable-ext-30001",
							"queue": "queue:node:0191c001-0000-7000-8000-000000000001:operations",
							"payload": map[string]interface{}{
								"operation_id":   "01a1187b-f08d-7fc1-a8fa-4abf88ce688d",
								"operation_type": "enable_external_access",
								"resource_id":    "01a114c4-b0df-7ef2-a680-8fef961e8daa",
								"project_id":     "proj-001",
								"environment_id": "env-001",
								"payload_json":   string(innerPayloadJSON),
							},
						}
						itemBytes, _ := json.Marshal(itemObj)
						itemStr := string(itemBytes)
						keyName := "queue:node:0191c001-0000-7000-8000-000000000001:operations"
						resp := fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(keyName), keyName, len(itemStr), itemStr)
						writer.WriteString(resp)
						writer.Flush()
					} else if cmdName == "SETEX" {
						writer.WriteString("+OK\r\n")
						writer.Flush()
					}
				}
			}(conn)
		}
	}()

	registry := operations.NewRegistry()
	registry.Register("enable_external_access", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		receivedEnvelopeChan <- op
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
		}, nil
	}, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := operations.NewDispatcher(registry, nil, nil, logger)
	consumer := NewValkeyConsumer(serverAddr, "0191c001-0000-7000-8000-000000000001", dispatcher, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = consumer.Start(ctx)
	}()

	select {
	case env := <-receivedEnvelopeChan:
		if env.OperationId != "01a1187b-f08d-7fc1-a8fa-4abf88ce688d" {
			t.Errorf("expected OperationId '01a1187b-f08d-7fc1-a8fa-4abf88ce688d', got '%s'", env.OperationId)
		}
		if env.OperationType != "enable_external_access" {
			t.Errorf("expected OperationType 'enable_external_access', got '%s'", env.OperationType)
		}

		var payloadMap map[string]interface{}
		if err := json.Unmarshal([]byte(env.PayloadJson), &payloadMap); err != nil {
			t.Fatalf("failed to unmarshal payload JSON: %v", err)
		}

		// Verify external_port is present and exactly 30001 (never 0)
		extPort, ok := payloadMap["external_port"]
		if !ok {
			t.Fatalf("expected payload_json to contain 'external_port', keys found: %v", payloadMap)
		}
		if int(extPort.(float64)) != 30001 {
			t.Errorf("expected external_port 30001, got %v", extPort)
		}

		port, ok := payloadMap["port"]
		if !ok {
			t.Fatalf("expected payload_json to contain 'port', keys found: %v", payloadMap)
		}
		if int(port.(float64)) != 30001 {
			t.Errorf("expected port 30001, got %v", port)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for real queue envelope test")
	}
}


