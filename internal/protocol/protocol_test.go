package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	msg := &Message{Type: MsgPing, Payload: nil}
	var buf bytes.Buffer

	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Type != MsgPing {
		t.Errorf("Type = %s, want Ping", got.Type)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(got.Payload))
	}
}

func TestWriteReadWithPayload(t *testing.T) {
	payload := []byte("test payload data")
	msg := &Message{Type: MsgError, Payload: payload}
	var buf bytes.Buffer

	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Type != MsgError {
		t.Errorf("Type = %s, want Error", got.Type)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload = %q, want %q", got.Payload, payload)
	}
}

func TestFrameFormat(t *testing.T) {
	payload := []byte("hello")
	msg := &Message{Type: MsgPing, Payload: payload}
	var buf bytes.Buffer

	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	frame := buf.Bytes()

	// Verify frame structure: [type:1][length:4][payload:5]
	if len(frame) != 1+4+5 {
		t.Fatalf("frame len = %d, want %d", len(frame), 10)
	}
	if frame[0] != byte(MsgPing) {
		t.Errorf("frame[0] = 0x%02x, want 0x%02x", frame[0], MsgPing)
	}
	length := binary.BigEndian.Uint32(frame[1:5])
	if length != 5 {
		t.Errorf("length = %d, want 5", length)
	}
	if !bytes.Equal(frame[5:], payload) {
		t.Errorf("frame payload = %q, want %q", frame[5:], payload)
	}
}

func TestMaxPayloadSizeEnforcement(t *testing.T) {
	// WriteMessage should reject payloads over MaxPayloadSize.
	bigPayload := make([]byte, MaxPayloadSize+1)
	msg := &Message{Type: MsgPing, Payload: bigPayload}
	var buf bytes.Buffer

	err := WriteMessage(&buf, msg)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("WriteMessage err = %v, want ErrPayloadTooLarge", err)
	}

	// ReadMessage should reject frames claiming a payload over MaxPayloadSize.
	var crafted bytes.Buffer
	header := make([]byte, 5)
	header[0] = byte(MsgPing)
	binary.BigEndian.PutUint32(header[1:5], MaxPayloadSize+1)
	crafted.Write(header)

	_, err = ReadMessage(&crafted)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("ReadMessage err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestReadMessageTruncatedHeader(t *testing.T) {
	// Only 3 bytes — less than the 5-byte header.
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00})
	_, err := ReadMessage(r)
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestReadMessageTruncatedPayload(t *testing.T) {
	// Header says 10 bytes of payload, but only 3 are present.
	var buf bytes.Buffer
	header := make([]byte, 5)
	header[0] = byte(MsgPing)
	binary.BigEndian.PutUint32(header[1:5], 10)
	buf.Write(header)
	buf.Write([]byte{1, 2, 3})

	_, err := ReadMessage(&buf)
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestMultipleMessagesOnStream(t *testing.T) {
	var buf bytes.Buffer

	msgs := []*Message{
		NewPing(),
		NewPong(),
		NewError("something went wrong"),
		{Type: MsgHandshake, Payload: []byte(`{"hostname":"test"}`)},
	}

	for _, msg := range msgs {
		if err := WriteMessage(&buf, msg); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}

	for i, want := range msgs {
		got, err := ReadMessage(&buf)
		if err != nil {
			t.Fatalf("ReadMessage[%d]: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("msg[%d] Type = %s, want %s", i, got.Type, want.Type)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("msg[%d] Payload = %q, want %q", i, got.Payload, want.Payload)
		}
	}

	// No more messages.
	_, err := ReadMessage(&buf)
	if err == nil {
		t.Error("expected EOF after all messages read")
	}
}

// --- Handshake ---

func TestHandshakeRoundTrip(t *testing.T) {
	original := &HandshakePayload{
		Hostname: "agent-01",
		OS:       "linux",
		IPs:      []string{"10.0.0.5", "192.168.1.100"},
		PID:      12345,
		Version:  "1.0.0",
	}

	msg, err := EncodeHandshake(original)
	if err != nil {
		t.Fatalf("EncodeHandshake: %v", err)
	}
	if msg.Type != MsgHandshake {
		t.Errorf("Type = %s, want Handshake", msg.Type)
	}

	// Write and read through the wire format.
	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeHandshake(wireMsg)
	if err != nil {
		t.Fatalf("DecodeHandshake: %v", err)
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname = %q, want %q", decoded.Hostname, original.Hostname)
	}
	if decoded.OS != original.OS {
		t.Errorf("OS = %q, want %q", decoded.OS, original.OS)
	}
	if len(decoded.IPs) != len(original.IPs) {
		t.Fatalf("IPs len = %d, want %d", len(decoded.IPs), len(original.IPs))
	}
	for i, ip := range decoded.IPs {
		if ip != original.IPs[i] {
			t.Errorf("IPs[%d] = %q, want %q", i, ip, original.IPs[i])
		}
	}
	if decoded.PID != original.PID {
		t.Errorf("PID = %d, want %d", decoded.PID, original.PID)
	}
	if decoded.Version != original.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, original.Version)
	}
}

func TestHandshakeTypeMismatch(t *testing.T) {
	msg := NewPing()
	_, err := DecodeHandshake(msg)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("err = %v, want ErrTypeMismatch", err)
	}
}

// --- HandshakeAck ---

func TestHandshakeAckRoundTrip(t *testing.T) {
	original := &HandshakeAckPayload{
		SessionID:    "sess-abc-123",
		ProxyVersion: "2.0.0",
	}

	msg, err := EncodeHandshakeAck(original)
	if err != nil {
		t.Fatalf("EncodeHandshakeAck: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeHandshakeAck(wireMsg)
	if err != nil {
		t.Fatalf("DecodeHandshakeAck: %v", err)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.ProxyVersion != original.ProxyVersion {
		t.Errorf("ProxyVersion = %q, want %q", decoded.ProxyVersion, original.ProxyVersion)
	}
}

// --- TunnelRequest ---

func TestTunnelRequestRoundTrip(t *testing.T) {
	original := &TunnelRequestPayload{
		ID:         "tun-001",
		Direction:  "reverse",
		ListenAddr: "0.0.0.0:8080",
		RemoteAddr: "10.0.0.5:3000",
		Protocol:   "tcp",
	}

	msg, err := EncodeTunnelRequest(original)
	if err != nil {
		t.Fatalf("EncodeTunnelRequest: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeTunnelRequest(wireMsg)
	if err != nil {
		t.Fatalf("DecodeTunnelRequest: %v", err)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Direction != original.Direction {
		t.Errorf("Direction = %q, want %q", decoded.Direction, original.Direction)
	}
	if decoded.ListenAddr != original.ListenAddr {
		t.Errorf("ListenAddr = %q, want %q", decoded.ListenAddr, original.ListenAddr)
	}
	if decoded.RemoteAddr != original.RemoteAddr {
		t.Errorf("RemoteAddr = %q, want %q", decoded.RemoteAddr, original.RemoteAddr)
	}
	if decoded.Protocol != original.Protocol {
		t.Errorf("Protocol = %q, want %q", decoded.Protocol, original.Protocol)
	}
}

// --- TunnelAck ---

func TestTunnelAckRoundTrip(t *testing.T) {
	original := &TunnelAckPayload{
		ID:        "tun-001",
		BoundAddr: "0.0.0.0:8080",
	}

	msg, err := EncodeTunnelAck(original)
	if err != nil {
		t.Fatalf("EncodeTunnelAck: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeTunnelAck(wireMsg)
	if err != nil {
		t.Fatalf("DecodeTunnelAck: %v", err)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.BoundAddr != original.BoundAddr {
		t.Errorf("BoundAddr = %q, want %q", decoded.BoundAddr, original.BoundAddr)
	}
	if decoded.Error != "" {
		t.Errorf("Error = %q, want empty", decoded.Error)
	}
}

func TestTunnelAckWithError(t *testing.T) {
	original := &TunnelAckPayload{
		ID:    "tun-002",
		Error: "address already in use",
	}

	msg, err := EncodeTunnelAck(original)
	if err != nil {
		t.Fatalf("EncodeTunnelAck: %v", err)
	}

	decoded, err := DecodeTunnelAck(msg)
	if err != nil {
		t.Fatalf("DecodeTunnelAck: %v", err)
	}
	if decoded.Error != original.Error {
		t.Errorf("Error = %q, want %q", decoded.Error, original.Error)
	}
}

// --- TunnelClose ---

func TestTunnelCloseRoundTrip(t *testing.T) {
	tunnelID := "tun-001"
	msg := EncodeTunnelClose(tunnelID)

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeTunnelClose(wireMsg)
	if err != nil {
		t.Fatalf("DecodeTunnelClose: %v", err)
	}
	if decoded != tunnelID {
		t.Errorf("tunnel ID = %q, want %q", decoded, tunnelID)
	}
}

// --- RouteAdd / RouteRemove ---

func TestRouteAddRoundTrip(t *testing.T) {
	original := &RoutePayload{CIDR: "10.0.0.0/24", Gateway: "10.0.0.1"}

	msg, err := EncodeRouteAdd(original)
	if err != nil {
		t.Fatalf("EncodeRouteAdd: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeRouteAdd(wireMsg)
	if err != nil {
		t.Fatalf("DecodeRouteAdd: %v", err)
	}
	if decoded.CIDR != original.CIDR {
		t.Errorf("CIDR = %q, want %q", decoded.CIDR, original.CIDR)
	}
	if decoded.Gateway != original.Gateway {
		t.Errorf("Gateway = %q, want %q", decoded.Gateway, original.Gateway)
	}
}

func TestRouteRemoveRoundTrip(t *testing.T) {
	original := &RoutePayload{CIDR: "172.16.0.0/16", Gateway: "172.16.0.1"}

	msg, err := EncodeRouteRemove(original)
	if err != nil {
		t.Fatalf("EncodeRouteRemove: %v", err)
	}

	decoded, err := DecodeRouteRemove(msg)
	if err != nil {
		t.Fatalf("DecodeRouteRemove: %v", err)
	}
	if decoded.CIDR != original.CIDR {
		t.Errorf("CIDR = %q, want %q", decoded.CIDR, original.CIDR)
	}
	if decoded.Gateway != original.Gateway {
		t.Errorf("Gateway = %q, want %q", decoded.Gateway, original.Gateway)
	}
}

// --- ListenerRequest / ListenerAck ---

func TestListenerRequestRoundTrip(t *testing.T) {
	original := &ListenerRequestPayload{
		ID:          "lst-001",
		ListenAddr:  "0.0.0.0:4444",
		ForwardAddr: "127.0.0.1:22",
	}

	msg, err := EncodeListenerRequest(original)
	if err != nil {
		t.Fatalf("EncodeListenerRequest: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeListenerRequest(wireMsg)
	if err != nil {
		t.Fatalf("DecodeListenerRequest: %v", err)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.ListenAddr != original.ListenAddr {
		t.Errorf("ListenAddr = %q, want %q", decoded.ListenAddr, original.ListenAddr)
	}
	if decoded.ForwardAddr != original.ForwardAddr {
		t.Errorf("ForwardAddr = %q, want %q", decoded.ForwardAddr, original.ForwardAddr)
	}
}

func TestListenerAckRoundTrip(t *testing.T) {
	original := &ListenerAckPayload{
		ID:        "lst-001",
		BoundAddr: "0.0.0.0:4444",
	}

	msg, err := EncodeListenerAck(original)
	if err != nil {
		t.Fatalf("EncodeListenerAck: %v", err)
	}

	decoded, err := DecodeListenerAck(msg)
	if err != nil {
		t.Fatalf("DecodeListenerAck: %v", err)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.BoundAddr != original.BoundAddr {
		t.Errorf("BoundAddr = %q, want %q", decoded.BoundAddr, original.BoundAddr)
	}
}

// --- Ping / Pong ---

func TestPingPong(t *testing.T) {
	var buf bytes.Buffer

	if err := WriteMessage(&buf, NewPing()); err != nil {
		t.Fatalf("WriteMessage Ping: %v", err)
	}
	if err := WriteMessage(&buf, NewPong()); err != nil {
		t.Fatalf("WriteMessage Pong: %v", err)
	}

	ping, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage Ping: %v", err)
	}
	if ping.Type != MsgPing {
		t.Errorf("Type = %s, want Ping", ping.Type)
	}

	pong, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage Pong: %v", err)
	}
	if pong.Type != MsgPong {
		t.Errorf("Type = %s, want Pong", pong.Type)
	}
}

// --- Error message ---

func TestErrorMessage(t *testing.T) {
	errMsg := "connection refused"
	msg := NewError(errMsg)

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	wireMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	decoded, err := DecodeError(wireMsg)
	if err != nil {
		t.Fatalf("DecodeError: %v", err)
	}
	if decoded != errMsg {
		t.Errorf("error = %q, want %q", decoded, errMsg)
	}
}

func TestDecodeErrorTypeMismatch(t *testing.T) {
	msg := NewPing()
	_, err := DecodeError(msg)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("err = %v, want ErrTypeMismatch", err)
	}
}

// --- MessageType.String ---

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		mt   MessageType
		want string
	}{
		{MsgHandshake, "Handshake"},
		{MsgHandshakeAck, "HandshakeAck"},
		{MsgTunnelRequest, "TunnelRequest"},
		{MsgTunnelAck, "TunnelAck"},
		{MsgTunnelClose, "TunnelClose"},
		{MsgRouteAdd, "RouteAdd"},
		{MsgRouteRemove, "RouteRemove"},
		{MsgListenerRequest, "ListenerRequest"},
		{MsgListenerAck, "ListenerAck"},
		{MsgPing, "Ping"},
		{MsgPong, "Pong"},
		{MsgError, "Error"},
		{MessageType(0xEE), "Unknown(0xee)"},
	}
	for _, tt := range tests {
		got := tt.mt.String()
		if got != tt.want {
			t.Errorf("MessageType(0x%02x).String() = %q, want %q", uint8(tt.mt), got, tt.want)
		}
	}
}

// --- Edge cases ---

func TestEmptyPayloadMessage(t *testing.T) {
	msg := &Message{Type: MsgPing, Payload: nil}
	var buf bytes.Buffer

	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	// Frame should be exactly 5 bytes (header only).
	if buf.Len() != 5 {
		t.Errorf("frame size = %d, want 5", buf.Len())
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Type != MsgPing {
		t.Errorf("Type = %s, want Ping", got.Type)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(got.Payload))
	}
}

func TestReadMessageEOF(t *testing.T) {
	r := &bytes.Buffer{}
	_, err := ReadMessage(r)
	if err == nil {
		t.Error("expected error on empty reader")
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "EOF") {
		t.Errorf("expected EOF-related error, got: %v", err)
	}
}

func TestExactMaxPayloadSize(t *testing.T) {
	// Exactly at the limit should succeed.
	payload := make([]byte, MaxPayloadSize)
	msg := &Message{Type: MsgPing, Payload: payload}
	var buf bytes.Buffer

	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage with max payload: %v", err)
	}

	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage with max payload: %v", err)
	}
	if len(got.Payload) != MaxPayloadSize {
		t.Errorf("Payload len = %d, want %d", len(got.Payload), MaxPayloadSize)
	}
}

// --- Type mismatch coverage for all decode functions ---

func TestAllDecodersRejectWrongType(t *testing.T) {
	wrong := NewPing()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"DecodeHandshake", func() error { _, err := DecodeHandshake(wrong); return err }},
		{"DecodeHandshakeAck", func() error { _, err := DecodeHandshakeAck(wrong); return err }},
		{"DecodeTunnelRequest", func() error { _, err := DecodeTunnelRequest(wrong); return err }},
		{"DecodeTunnelAck", func() error { _, err := DecodeTunnelAck(wrong); return err }},
		{"DecodeTunnelClose", func() error { _, err := DecodeTunnelClose(wrong); return err }},
		{"DecodeRouteAdd", func() error { _, err := DecodeRouteAdd(wrong); return err }},
		{"DecodeRouteRemove", func() error { _, err := DecodeRouteRemove(wrong); return err }},
		{"DecodeListenerRequest", func() error { _, err := DecodeListenerRequest(wrong); return err }},
		{"DecodeListenerAck", func() error { _, err := DecodeListenerAck(wrong); return err }},
		{"DecodeError", func() error { _, err := DecodeError(wrong); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if !errors.Is(err, ErrTypeMismatch) {
				t.Errorf("%s: err = %v, want ErrTypeMismatch", tt.name, err)
			}
		})
	}
}
