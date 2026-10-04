package haproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TCPForwarder is a local Layer-4 TCP stream proxy matching HAProxy's mode tcp forwarding.
type TCPForwarder struct {
	mu       sync.Mutex
	listener net.Listener
	target   string
	conns    []net.Conn
	closed   bool
}

func startTCPForwarder(listenAddr, targetAddr string) (*TCPForwarder, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	fwd := &TCPForwarder{
		listener: ln,
		target:   targetAddr,
		conns:    make([]net.Conn, 0),
	}
	go func() {
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				return
			}
			targetConn, err := net.DialTimeout("tcp", fwd.target, 2*time.Second)
			if err != nil {
				clientConn.Close()
				continue
			}

			fwd.mu.Lock()
			if fwd.closed {
				fwd.mu.Unlock()
				clientConn.Close()
				targetConn.Close()
				return
			}
			fwd.conns = append(fwd.conns, clientConn, targetConn)
			fwd.mu.Unlock()

			go func(c, t net.Conn) {
				defer c.Close()
				defer t.Close()
				go func() {
					_, _ = io.Copy(t, c)
				}()
				_, _ = io.Copy(c, t)
			}(clientConn, targetConn)
		}
	}()
	return fwd, nil
}

func (f *TCPForwarder) Close() error {
	f.mu.Lock()
	f.closed = true
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	return f.listener.Close()
}

func (f *TCPForwarder) Addr() string {
	return f.listener.Addr().String()
}

// TestPostgresRawTCPForwarding verifies end-to-end Layer 4 TCP byte forwarding
// for PostgreSQL protocol startup, authentication, and SELECT 1 query execution.
func TestPostgresRawTCPForwarding(t *testing.T) {
	// 1. Start mock PostgreSQL backend
	pgBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start pg backend: %v", err)
	}
	defer pgBackendLn.Close()
	pgBackendAddr := pgBackendLn.Addr().String()

	go func() {
		conn, err := pgBackendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read Startup packet (length int32, protocol int32, params...)
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		packetLen := binary.BigEndian.Uint32(lenBuf)
		body := make([]byte, packetLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		// Send AuthenticationOk ('R', len 8, 0)
		authOk := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
		conn.Write(authOk)

		// Send ReadyForQuery ('Z', len 5, 'I')
		ready := []byte{'Z', 0, 0, 0, 5, 'I'}
		conn.Write(ready)

		// Read Query message ('Q', len int32, query string)
		qType := make([]byte, 1)
		if _, err := io.ReadFull(conn, qType); err != nil {
			return
		}
		if qType[0] == 'Q' {
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			qLen := binary.BigEndian.Uint32(lenBuf)
			queryBuf := make([]byte, qLen-4)
			if _, err := io.ReadFull(conn, queryBuf); err != nil {
				return
			}
			queryStr := strings.TrimRight(string(queryBuf), "\x00")
			if strings.Contains(queryStr, "SELECT 1") {
				// Send DataRow ('D', len 11, col count 1, col len 1, '1')
				dataRow := []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '1'}
				conn.Write(dataRow)
				// Send CommandComplete ('C', len 13, "SELECT 1\0")
				cmdComplete := append([]byte{'C', 0, 0, 0, 13}, []byte("SELECT 1\x00")...)
				conn.Write(cmdComplete)
				// Send ReadyForQuery
				conn.Write(ready)
			}
		}
	}()

	// 2. Start TCP Forwarder simulating HAProxy mode tcp gateway
	gatewayFwd, err := startTCPForwarder("127.0.0.1:0", pgBackendAddr)
	if err != nil {
		t.Fatalf("failed to start gateway forwarder: %v", err)
	}
	defer gatewayFwd.Close()
	gatewayAddr := gatewayFwd.Addr()

	// 3. Connect external client to Gateway and run PostgreSQL handshake & query
	clientConn, err := net.DialTimeout("tcp", gatewayAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("external client failed to connect to gateway: %v", err)
	}
	defer clientConn.Close()

	// Send PG Startup Packet (Proto 3.0)
	var startupBuf bytes.Buffer
	binary.Write(&startupBuf, binary.BigEndian, int32(0)) // placeholder for len
	binary.Write(&startupBuf, binary.BigEndian, int32(196608)) // 3.0 protocol
	startupBuf.WriteString("user\x00primecloud\x00database\x00app\x00\x00")
	startupBytes := startupBuf.Bytes()
	binary.BigEndian.PutUint32(startupBytes[0:4], uint32(len(startupBytes)))
	clientConn.Write(startupBytes)

	// Read AuthOk ('R' + 8 bytes payload)
	respType := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, respType); err != nil {
		t.Fatalf("failed to read AuthOk from gateway: %v", err)
	}
	if respType[0] != 'R' {
		t.Fatalf("expected AuthOk 'R', got %c", respType[0])
	}
	authPayload := make([]byte, 8)
	if _, err := io.ReadFull(clientConn, authPayload); err != nil {
		t.Fatalf("failed to read AuthOk payload: %v", err)
	}

	// Read ReadyForQuery ('Z' + 5 bytes payload)
	if _, err := io.ReadFull(clientConn, respType); err != nil {
		t.Fatalf("failed to read ReadyForQuery from gateway: %v", err)
	}
	if respType[0] != 'Z' {
		t.Fatalf("expected ReadyForQuery 'Z', got %c", respType[0])
	}
	readyPayload := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, readyPayload); err != nil {
		t.Fatalf("failed to read ReadyForQuery payload: %v", err)
	}

	// Send Query: SELECT 1;
	query := "SELECT 1;\x00"
	var qBuf bytes.Buffer
	qBuf.WriteByte('Q')
	binary.Write(&qBuf, binary.BigEndian, int32(len(query)+4))
	qBuf.WriteString(query)
	clientConn.Write(qBuf.Bytes())

	// Read DataRow ('D' + length + data)
	if _, err := io.ReadFull(clientConn, respType); err != nil {
		t.Fatalf("failed to read DataRow header: %v", err)
	}
	if respType[0] != 'D' {
		t.Fatalf("expected DataRow 'D', got %c", respType[0])
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
		t.Fatalf("failed to read DataRow length: %v", err)
	}
	dLen := binary.BigEndian.Uint32(lenBuf)
	dBody := make([]byte, dLen-4)
	if _, err := io.ReadFull(clientConn, dBody); err != nil {
		t.Fatalf("failed to read DataRow body: %v", err)
	}

	// Extract value ('1') from DataRow (2 bytes col count = 1, 4 bytes col len = 1, 1 byte char '1')
	val := string(dBody[6:])
	if val != "1" {
		t.Fatalf("expected query result '1', got %q", val)
	}
}

// TestValkeyRawTCPForwarding verifies end-to-end Layer 4 TCP byte forwarding
// for Valkey/Redis AUTH and PING -> PONG wire protocol.
func TestValkeyRawTCPForwarding(t *testing.T) {
	// 1. Start mock Valkey backend
	vkBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start valkey backend: %v", err)
	}
	defer vkBackendLn.Close()
	vkBackendAddr := vkBackendLn.Addr().String()

	go func() {
		conn, err := vkBackendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "*2") {
				// Read AUTH command arguments ($4\r\nAUTH\r\n$6\r\nsecret\r\n)
				_, _ = reader.ReadString('\n')
				_, _ = reader.ReadString('\n')
				_, _ = reader.ReadString('\n')
				_, _ = reader.ReadString('\n')
				conn.Write([]byte("+OK\r\n"))
			} else if strings.HasPrefix(line, "*1") {
				// Read PING command arguments ($4\r\nPING\r\n)
				_, _ = reader.ReadString('\n')
				_, _ = reader.ReadString('\n')
				conn.Write([]byte("+PONG\r\n"))
			}
		}
	}()

	// 2. Start TCP Gateway Forwarder
	gatewayFwd, err := startTCPForwarder("127.0.0.1:0", vkBackendAddr)
	if err != nil {
		t.Fatalf("failed to start gateway forwarder: %v", err)
	}
	defer gatewayFwd.Close()

	// 3. Client connects to Gateway
	clientConn, err := net.DialTimeout("tcp", gatewayFwd.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("client failed to connect to gateway: %v", err)
	}
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	// Send AUTH secret
	clientConn.Write([]byte("*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"))
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read AUTH response: %v", err)
	}
	if strings.TrimSpace(authResp) != "+OK" {
		t.Fatalf("expected +OK, got %s", authResp)
	}

	// Send PING
	clientConn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	pingResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read PING response: %v", err)
	}
	if strings.TrimSpace(pingResp) != "+PONG" {
		t.Fatalf("expected +PONG, got %s", pingResp)
	}
}

// TestDisableExternalAccessRefusesConnection verifies that closing/disabling
// the gateway route results in immediate connection refusal.
func TestDisableExternalAccessRefusesConnection(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on backend: %v", err)
	}
	defer backendLn.Close()

	gatewayFwd, err := startTCPForwarder("127.0.0.1:0", backendLn.Addr().String())
	if err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	gatewayAddr := gatewayFwd.Addr()

	// 1. Verify connection works when enabled
	conn1, err := net.DialTimeout("tcp", gatewayAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("expected connection to succeed while active: %v", err)
	}
	conn1.Close()

	// 2. Disable gateway route
	if err := gatewayFwd.Close(); err != nil {
		t.Fatalf("failed to close gateway: %v", err)
	}

	// 3. Verify connection fails immediately
	_, err = net.DialTimeout("tcp", gatewayAddr, 500*time.Millisecond)
	if err == nil {
		t.Fatalf("expected connection refused after gateway disabled, but connection succeeded")
	}
}

// TestMultiResourceTenantIsolation verifies that Port A routes strictly to Target A
// and Port B routes strictly to Target B with zero cross-talk.
func TestMultiResourceTenantIsolation(t *testing.T) {
	// Backend A
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen lnA: %v", err)
	}
	defer lnA.Close()
	go func() {
		for {
			c, err := lnA.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("TARGET_POSTGRES_A\n"))
			c.Close()
		}
	}()

	// Backend B
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen lnB: %v", err)
	}
	defer lnB.Close()
	go func() {
		for {
			c, err := lnB.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("TARGET_POSTGRES_B\n"))
			c.Close()
		}
	}()

	// Gateway A -> Target A
	fwdA, err := startTCPForwarder("127.0.0.1:0", lnA.Addr().String())
	if err != nil {
		t.Fatalf("failed to start fwdA: %v", err)
	}
	defer fwdA.Close()

	// Gateway B -> Target B
	fwdB, err := startTCPForwarder("127.0.0.1:0", lnB.Addr().String())
	if err != nil {
		t.Fatalf("failed to start fwdB: %v", err)
	}
	defer fwdB.Close()

	// Query Gateway A
	cA, err := net.DialTimeout("tcp", fwdA.Addr(), 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial fwdA: %v", err)
	}
	respA, _ := bufio.NewReader(cA).ReadString('\n')
	cA.Close()
	if strings.TrimSpace(respA) != "TARGET_POSTGRES_A" {
		t.Fatalf("expected TARGET_POSTGRES_A, got %q", respA)
	}

	// Query Gateway B
	cB, err := net.DialTimeout("tcp", fwdB.Addr(), 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial fwdB: %v", err)
	}
	respB, _ := bufio.NewReader(cB).ReadString('\n')
	cB.Close()
	if strings.TrimSpace(respB) != "TARGET_POSTGRES_B" {
		t.Fatalf("expected TARGET_POSTGRES_B, got %q", respB)
	}
}
