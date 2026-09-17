# PrimeCloud Agent Transport Protocol Specification

**Document ID:** PCA-DOCS-TRANSPORT-PROTOCOL  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE PROTOCOL SPECIFICATION  

---

## 1. Overview

The PrimeCloud Agent connects **outbound** from each compute node to the Control Plane boundary. The transport strictly enforces:
- **Transport Security:** Mutual TLS (mTLS) with certificates issued by HashiCorp Vault PKI (`pki_int/issue/agent`).
- **Wire Format:** Protocol Buffers v3 (`proto/agent.proto`).
- **RPC Framework:** gRPC with HTTP/2 and bidirectional streaming.
- **Directionality:** Outbound from Agent to Control Plane. The Agent never opens an inbound administration port.

---

## 2. Service Definition

The core service is `primecloud.agent.v1.AgentService`:

```protobuf
service AgentService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc StreamOperations(stream OperationResponse) returns (stream OperationEnvelope);
  rpc SendHeartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc ReportInventory(InventoryRequest) returns (InventoryResponse);
  rpc ReportState(StateRequest) returns (StateResponse);
  rpc ReportEvent(EventRequest) returns (EventResponse);
  rpc ReportMetrics(MetricsRequest) returns (MetricsResponse);
  rpc Reconcile(ReconcileRequest) returns (ReconcileResponse);
}
```

---

## 3. Communication Mechanics

### 3.1 Initial Handshake (Register)
Upon startup and certificate loading:
1. Agent dials Control Plane over mTLS.
2. Agent calls `Register(RegisterRequest)` passing node hardware metrics, kernel version, hostname, Docker version, and certificate Common Name (CN).
3. Control Plane verifies CN, records node in database, and returns `agent_id`, `node_id`, and capability assignments.

### 3.2 Operation Streaming (StreamOperations)
A persistent bidirectional gRPC stream:
- **Server to Client (`OperationEnvelope`):** Control Plane dispatches strictly typed operations (`deploy_application`, `provision_postgres`, etc.) containing immutable JSON payloads.
- **Client to Server (`OperationResponse`):** Agent streams progress updates (`RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`) with telemetry and execution outputs.

### 3.3 Heartbeats & Keepalives
- Agent sends a `HeartbeatRequest` every 10 seconds (configurable) reporting CPU, memory, disk utilization, container count, and node health (`HEALTHY`, `DEGRADED`, `UNHEALTHY`).
- Control Plane responds with directives including `rotate_certificate` or `trigger_reconciliation`.

### 3.4 Reconnection and Resilience
- If the gRPC connection drops, the Agent initiates an exponential backoff loop with randomized jitter:
  $$\text{Delay} = \min(\text{BaseDelay} \times 2^{\text{attempt}}, \text{MaxDelay}) + \text{Jitter}$$
- Max retry backoff is capped at 30 seconds.
- In-flight operations continue safely using local locks and persist their state until connectivity is restored.
