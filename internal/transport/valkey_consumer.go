// Package transport provides mTLS configuration, gRPC client connections, Valkey queue consumer, and automatic reconnection mechanics.
package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/operations"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

// ValkeyConsumer consumes node operations from Valkey queue and publishes correlated results.
type ValkeyConsumer struct {
	queueURL   string
	nodeID     string
	queueKey   string
	dispatcher *operations.Dispatcher
	logger     *slog.Logger
}

// NewValkeyConsumer constructs a ValkeyConsumer.
func NewValkeyConsumer(queueURL, nodeID string, dispatcher *operations.Dispatcher, logger *slog.Logger) *ValkeyConsumer {
	if logger == nil {
		logger = slog.Default()
	}
	if nodeID == "" {
		nodeID = "0191c001-0000-7000-8000-000000000001"
	}
	return &ValkeyConsumer{
		queueURL:   queueURL,
		nodeID:     nodeID,
		queueKey:   fmt.Sprintf("queue:node:%s:operations", nodeID),
		dispatcher: dispatcher,
		logger:     logger.With("component", "valkey_consumer"),
	}
}

func normalizeValkeyAddr(raw string) string {
	addr := strings.TrimSpace(raw)
	if strings.HasPrefix(addr, "redis://") {
		addr = strings.TrimPrefix(addr, "redis://")
	} else if strings.HasPrefix(addr, "valkey://") {
		addr = strings.TrimPrefix(addr, "valkey://")
	}
	// Strip trailing slash and database index if present (e.g. /0)
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	return addr
}

// Start begins the consumer event loop, retrying connections automatically until context is cancelled.
func (vc *ValkeyConsumer) Start(ctx context.Context) error {
	vc.logger.Info("primecloud_operation_transport_starting",
		"queue_url", vc.queueURL,
		"node_id", vc.nodeID,
		"queue_key", vc.queueKey,
	)

	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			vc.logger.Info("primecloud_operation_consumer_stopping")
			return nil
		default:
		}

		err := vc.runConsumerLoop(ctx)
		if err != nil && ctx.Err() == nil {
			vc.logger.Warn("valkey_consumer_reconnecting",
				"error", err.Error(),
				"backoff", backoff.String(),
				"queue_key", vc.queueKey,
			)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = 500 * time.Millisecond
		}
	}
}

func (vc *ValkeyConsumer) runConsumerLoop(ctx context.Context) error {
	addr := normalizeValkeyAddr(vc.queueURL)

	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to valkey broker at %s: %w", addr, err)
	}
	defer conn.Close()

	vc.logger.Info("valkey_consumer_connected", "queue_url", vc.queueURL, "addr", addr, "queue_key", vc.queueKey)
	vc.logger.Info("primecloud_operation_transport_connected", "queue_url", vc.queueURL)
	vc.logger.Info("primecloud_operation_consumer_ready", "queue_key", vc.queueKey)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// BLPOP queue:node:{node_id}:operations 2
		cmd := fmt.Sprintf("*3\r\n$5\r\nBLPOP\r\n$%d\r\n%s\r\n$1\r\n2\r\n", len(vc.queueKey), vc.queueKey)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := writer.WriteString(cmd); err != nil {
			vc.logger.Error("valkey_consumer_read_error", "stage", "write_blpop", "error", err)
			return fmt.Errorf("valkey consumer write error: %w", err)
		}
		if err := writer.Flush(); err != nil {
			vc.logger.Error("valkey_consumer_read_error", "stage", "flush_blpop", "error", err)
			return fmt.Errorf("valkey consumer flush error: %w", err)
		}

		// Read deadline must exceed the BLPOP 2-second timeout (e.g. 7 seconds).
		// If deadline expires without response, connection is dead or hung; must reconnect.
		conn.SetReadDeadline(time.Now().Add(7 * time.Second))
		reply, err := parseRESP(reader)
		if err != nil {
			vc.logger.Error("valkey_consumer_read_error", "stage", "parse_resp", "error", err, "queue_key", vc.queueKey)
			return fmt.Errorf("valkey consumer read/parse error: %w", err)
		}

		// Normal 2-second BLPOP timeout returns nil array (*-1\r\n) with no error.
		if reply == nil {
			continue
		}

		items, ok := reply.([]interface{})
		if !ok || len(items) < 2 {
			vc.logger.Error("valkey_consumer_read_error", "stage", "invalid_blpop_reply_format", "reply", reply)
			return fmt.Errorf("unexpected BLPOP response format: %v", reply)
		}

		rawItemStr, ok := items[1].(string)
		if !ok || rawItemStr == "" {
			vc.logger.Warn("valkey_consumer_empty_item", "reply", reply)
			continue
		}

		vc.processItem(ctx, rawItemStr)
	}
}

func (vc *ValkeyConsumer) processItem(ctx context.Context, rawItemStr string) {
	startTime := time.Now()

	var rawObj map[string]interface{}
	if err := json.Unmarshal([]byte(rawItemStr), &rawObj); err != nil {
		vc.logger.Error("valkey_consumer_unmarshal_failed", "raw", rawItemStr, "error", err)
		return
	}

	payloadMap := rawObj
	if p, ok := rawObj["payload"].(map[string]interface{}); ok {
		payloadMap = p
	}

	opID, _ := payloadMap["operation_id"].(string)
	if opID == "" {
		if id, ok := rawObj["id"].(string); ok {
			opID = id
		}
	}
	opType, _ := payloadMap["operation_type"].(string)

	resourceID, _ := payloadMap["resource_id"].(string)
	if resourceID == "" {
		resourceID, _ = payloadMap["application_id"].(string)
	}
	if resourceID == "" {
		if params, ok := payloadMap["parameters"].(map[string]interface{}); ok {
			resourceID, _ = params["resource_id"].(string)
			if resourceID == "" {
				resourceID, _ = params["application_id"].(string)
			}
		}
	}

	projectID, _ := payloadMap["project_id"].(string)
	if projectID == "" {
		if params, ok := payloadMap["parameters"].(map[string]interface{}); ok {
			projectID, _ = params["project_id"].(string)
		}
	}

	envID, _ := payloadMap["environment_id"].(string)
	if envID == "" {
		if params, ok := payloadMap["parameters"].(map[string]interface{}); ok {
			envID, _ = params["environment_id"].(string)
		}
	}

	var payloadJSON string
	if pjStr, ok := payloadMap["payload_json"].(string); ok {
		payloadJSON = pjStr
	} else if pObj, ok := payloadMap["payload_json"].(map[string]interface{}); ok {
		b, _ := json.Marshal(pObj)
		payloadJSON = string(b)
	} else if pObj, ok := payloadMap["payload"].(map[string]interface{}); ok && len(pObj) > 0 {
		b, _ := json.Marshal(pObj)
		payloadJSON = string(b)
	} else if params, ok := payloadMap["parameters"].(map[string]interface{}); ok {
		b, _ := json.Marshal(params)
		payloadJSON = string(b)
	} else {
		b, _ := json.Marshal(payloadMap)
		payloadJSON = string(b)
	}

	env := &pb.OperationEnvelope{
		OperationId:   opID,
		OperationType: opType,
		ResourceId:    resourceID,
		ProjectId:     projectID,
		EnvironmentId: envID,
		PayloadJson:   payloadJSON,
	}

	vc.logger.Info("primecloud_operation_received",
		"operation_id", env.OperationId,
		"operation_type", env.OperationType,
		"queue_key", vc.queueKey,
	)

	vc.logger.Info("primecloud_operation_executing",
		"operation_id", env.OperationId,
		"operation_type", env.OperationType,
		"resource_id", env.ResourceId,
	)

	resp, dispatchErr := vc.dispatcher.Dispatch(ctx, env)
	duration := time.Since(startTime)

	resultData := make(map[string]interface{})
	resultData["operation_id"] = env.OperationId
	resultData["node_id"] = vc.nodeID

	if dispatchErr != nil || (resp != nil && resp.Status == "FAILED") {
		errMsg := "dispatch error"
		if dispatchErr != nil {
			errMsg = dispatchErr.Error()
		} else if resp != nil {
			errMsg = resp.Message
		}
		vc.logger.Error("primecloud_operation_failed",
			"operation_id", env.OperationId,
			"error", errMsg,
			"duration_ms", duration.Milliseconds(),
		)

		resultData["status"] = "FAILED"
		resultData["success"] = false
		resultData["error_code"] = "EXECUTION_FAILED"
		if resp != nil && resp.ErrorCode != "" {
			resultData["error_code"] = resp.ErrorCode
		}
		resultData["error_message"] = errMsg
		resultData["message"] = errMsg
	} else {
		vc.logger.Info("primecloud_operation_completed",
			"operation_id", env.OperationId,
			"status", "SUCCEEDED",
			"duration_ms", duration.Milliseconds(),
		)

		resultData["status"] = "SUCCEEDED"
		resultData["success"] = true
		if resp != nil {
			resultData["message"] = resp.Message
			resultData["result_json"] = resp.ResultJson
			var subData map[string]interface{}
			if resp.ResultJson != "" && json.Unmarshal([]byte(resp.ResultJson), &subData) == nil {
				resultData["data"] = subData
			} else {
				resultData["data"] = map[string]interface{}{"status": "SUCCEEDED", "node_id": vc.nodeID}
			}
		}
	}

	resultBytes, _ := json.Marshal(resultData)
	vc.publishResult(env.OperationId, string(resultBytes))
}

// publishResult writes correlated operation results using a dedicated connection,
// ensuring the consumer BLPOP TCP stream is never contaminated.
func (vc *ValkeyConsumer) publishResult(opID, resultJSON string) {
	key := fmt.Sprintf("operation:%s:result", opID)
	ttl := "300"
	addr := normalizeValkeyAddr(vc.queueURL)

	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		vc.logger.Error("valkey_consumer_publish_result_dial_failed", "operation_id", opID, "error", err)
		return
	}
	defer conn.Close()

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	cmd := fmt.Sprintf("*4\r\n$5\r\nSETEX\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		len(key), key, len(ttl), ttl, len(resultJSON), resultJSON)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := writer.WriteString(cmd); err != nil {
		vc.logger.Error("valkey_consumer_publish_result_write_failed", "operation_id", opID, "error", err)
		return
	}
	if err := writer.Flush(); err != nil {
		vc.logger.Error("valkey_consumer_publish_result_flush_failed", "operation_id", opID, "error", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = parseRESP(reader)
	if err != nil {
		vc.logger.Error("valkey_consumer_publish_result_reply_failed", "operation_id", opID, "error", err)
		return
	}
	vc.logger.Info("valkey_consumer_result_published", "key", key)
}

func parseRESP(r *bufio.Reader) (interface{}, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, nil
	}

	prefix := line[0]
	content := line[1:]

	switch prefix {
	case '+':
		return content, nil
	case '-':
		return nil, fmt.Errorf("redis error: %s", content)
	case ':':
		return strconv.ParseInt(content, 10, 64)
	case '$':
		n, err := strconv.Atoi(content)
		if err != nil || n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(content)
		if err != nil || n < 0 {
			return nil, nil
		}
		if n == 0 {
			return []interface{}{}, nil
		}
		arr := make([]interface{}, n)
		for i := 0; i < n; i++ {
			elem, err := parseRESP(r)
			if err != nil {
				return nil, err
			}
			arr[i] = elem
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unknown RESP prefix: %c", prefix)
	}
}
