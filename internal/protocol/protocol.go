// Package protocol defines the binary message framing and typed payloads
// for agent-proxy communication in Burrow.
//
// Frame format: [type:1][length:4 big-endian][payload:length]
// All structured payloads are JSON-encoded for simplicity and debuggability.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxPayloadSize is the maximum allowed payload size (1 MB).
const MaxPayloadSize = 1 << 20 // 1 MB

// frameHeaderSize is type (1 byte) + length (4 bytes).
const frameHeaderSize = 5

// MessageType identifies the kind of protocol message.
type MessageType uint8

const (
	// MsgHandshake is sent by the agent to identify itself.
	MsgHandshake MessageType = 0x01
	// MsgHandshakeAck is sent by the proxy to acknowledge and assign a session ID.
	MsgHandshakeAck MessageType = 0x02

	// MsgTunnelRequest is sent by the proxy to request a tunnel.
	MsgTunnelRequest MessageType = 0x10
	// MsgTunnelAck is sent by the agent to confirm a tunnel is active.
	MsgTunnelAck MessageType = 0x11
	// MsgTunnelClose is sent by either side to close a tunnel.
	MsgTunnelClose MessageType = 0x12

	// MsgRouteAdd is sent by the proxy to add a network route.
	MsgRouteAdd MessageType = 0x20
	// MsgRouteRemove is sent by the proxy to remove a network route.
	MsgRouteRemove MessageType = 0x21

	// MsgListenerRequest is sent by the proxy to request a listener on the agent.
	MsgListenerRequest MessageType = 0x30
	// MsgListenerAck is sent by the agent to confirm a listener is active.
	MsgListenerAck MessageType = 0x31

	// MsgPing is a keepalive request.
	MsgPing MessageType = 0x40
	// MsgPong is a keepalive response.
	MsgPong MessageType = 0x41

	// MsgTunStart is sent by the proxy to request TUN mode activation.
	MsgTunStart MessageType = 0x50
	// MsgTunStartAck is sent by the agent to confirm TUN mode is active.
	MsgTunStartAck MessageType = 0x51
	// MsgTunStop is sent by the proxy to deactivate TUN mode.
	MsgTunStop MessageType = 0x52

	// MsgError carries an error string.
	MsgError MessageType = 0xFF
)

// String returns a human-readable name for the message type.
func (m MessageType) String() string {
	switch m {
	case MsgHandshake:
		return "Handshake"
	case MsgHandshakeAck:
		return "HandshakeAck"
	case MsgTunnelRequest:
		return "TunnelRequest"
	case MsgTunnelAck:
		return "TunnelAck"
	case MsgTunnelClose:
		return "TunnelClose"
	case MsgRouteAdd:
		return "RouteAdd"
	case MsgRouteRemove:
		return "RouteRemove"
	case MsgListenerRequest:
		return "ListenerRequest"
	case MsgListenerAck:
		return "ListenerAck"
	case MsgPing:
		return "Ping"
	case MsgPong:
		return "Pong"
	case MsgTunStart:
		return "TunStart"
	case MsgTunStartAck:
		return "TunStartAck"
	case MsgTunStop:
		return "TunStop"
	case MsgError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", uint8(m))
	}
}

// Errors returned by protocol operations.
var (
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
	ErrInvalidMessage  = errors.New("invalid message")
	ErrTypeMismatch    = errors.New("message type mismatch")
)

// Message is the fundamental unit of the protocol.
type Message struct {
	Type    MessageType
	Payload []byte
}

// --- Payload types ---

// HandshakePayload is sent by the agent to identify itself to the proxy.
type HandshakePayload struct {
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	IPs      []string `json:"ips"`
	PID      int      `json:"pid"`
	Version  string   `json:"version"`
}

// HandshakeAckPayload is sent by the proxy to acknowledge the agent.
type HandshakeAckPayload struct {
	SessionID    string `json:"session_id"`
	ProxyVersion string `json:"proxy_version"`
}

// TunnelRequestPayload is sent by the proxy to request a tunnel.
type TunnelRequestPayload struct {
	ID         string `json:"id"`
	Direction  string `json:"direction"` // "local", "remote", or "reverse"
	ListenAddr string `json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"` // "tcp" or "udp"
}

// TunnelAckPayload is sent by the agent to confirm a tunnel.
type TunnelAckPayload struct {
	ID        string `json:"id"`
	BoundAddr string `json:"bound_addr"`
	Error     string `json:"error,omitempty"`
}

// RoutePayload describes a network route to add or remove.
type RoutePayload struct {
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
}

// ListenerRequestPayload is sent by the proxy to request a listener.
type ListenerRequestPayload struct {
	ID          string `json:"id"`
	ListenAddr  string `json:"listen_addr"`
	ForwardAddr string `json:"forward_addr"`
}

// ListenerAckPayload is sent by the agent to confirm a listener.
type ListenerAckPayload struct {
	ID        string `json:"id"`
	BoundAddr string `json:"bound_addr"`
	Error     string `json:"error,omitempty"`
}

// --- Wire format ---

// WriteMessage writes a framed message to w.
// Frame format: [type:1][length:4 big-endian][payload:length]
func WriteMessage(w io.Writer, msg *Message) error {
	if len(msg.Payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	header := make([]byte, frameHeaderSize)
	header[0] = byte(msg.Type)
	binary.BigEndian.PutUint32(header[1:5], uint32(len(msg.Payload)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

// ReadMessage reads a framed message from r.
// Returns ErrPayloadTooLarge if the payload exceeds MaxPayloadSize.
func ReadMessage(r io.Reader) (*Message, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	msgType := MessageType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])

	if length > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Message{Type: msgType, Payload: payload}, nil
}

// --- Encode/Decode helpers ---

// EncodeHandshake creates a Handshake message from the given payload.
func EncodeHandshake(p *HandshakePayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal handshake: %w", err)
	}
	return &Message{Type: MsgHandshake, Payload: data}, nil
}

// DecodeHandshake extracts a HandshakePayload from a message.
func DecodeHandshake(msg *Message) (*HandshakePayload, error) {
	if msg.Type != MsgHandshake {
		return nil, fmt.Errorf("%w: got %s, want Handshake", ErrTypeMismatch, msg.Type)
	}
	var p HandshakePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal handshake: %w", err)
	}
	return &p, nil
}

// EncodeHandshakeAck creates a HandshakeAck message from the given payload.
func EncodeHandshakeAck(p *HandshakeAckPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal handshake ack: %w", err)
	}
	return &Message{Type: MsgHandshakeAck, Payload: data}, nil
}

// DecodeHandshakeAck extracts a HandshakeAckPayload from a message.
func DecodeHandshakeAck(msg *Message) (*HandshakeAckPayload, error) {
	if msg.Type != MsgHandshakeAck {
		return nil, fmt.Errorf("%w: got %s, want HandshakeAck", ErrTypeMismatch, msg.Type)
	}
	var p HandshakeAckPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal handshake ack: %w", err)
	}
	return &p, nil
}

// EncodeTunnelRequest creates a TunnelRequest message from the given payload.
func EncodeTunnelRequest(p *TunnelRequestPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal tunnel request: %w", err)
	}
	return &Message{Type: MsgTunnelRequest, Payload: data}, nil
}

// DecodeTunnelRequest extracts a TunnelRequestPayload from a message.
func DecodeTunnelRequest(msg *Message) (*TunnelRequestPayload, error) {
	if msg.Type != MsgTunnelRequest {
		return nil, fmt.Errorf("%w: got %s, want TunnelRequest", ErrTypeMismatch, msg.Type)
	}
	var p TunnelRequestPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal tunnel request: %w", err)
	}
	return &p, nil
}

// EncodeTunnelAck creates a TunnelAck message from the given payload.
func EncodeTunnelAck(p *TunnelAckPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal tunnel ack: %w", err)
	}
	return &Message{Type: MsgTunnelAck, Payload: data}, nil
}

// DecodeTunnelAck extracts a TunnelAckPayload from a message.
func DecodeTunnelAck(msg *Message) (*TunnelAckPayload, error) {
	if msg.Type != MsgTunnelAck {
		return nil, fmt.Errorf("%w: got %s, want TunnelAck", ErrTypeMismatch, msg.Type)
	}
	var p TunnelAckPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal tunnel ack: %w", err)
	}
	return &p, nil
}

// EncodeTunnelClose creates a TunnelClose message. The payload is the tunnel ID as raw bytes.
func EncodeTunnelClose(tunnelID string) *Message {
	return &Message{Type: MsgTunnelClose, Payload: []byte(tunnelID)}
}

// DecodeTunnelClose extracts the tunnel ID from a TunnelClose message.
func DecodeTunnelClose(msg *Message) (string, error) {
	if msg.Type != MsgTunnelClose {
		return "", fmt.Errorf("%w: got %s, want TunnelClose", ErrTypeMismatch, msg.Type)
	}
	return string(msg.Payload), nil
}

// EncodeRouteAdd creates a RouteAdd message from the given payload.
func EncodeRouteAdd(p *RoutePayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal route add: %w", err)
	}
	return &Message{Type: MsgRouteAdd, Payload: data}, nil
}

// DecodeRouteAdd extracts a RoutePayload from a RouteAdd message.
func DecodeRouteAdd(msg *Message) (*RoutePayload, error) {
	if msg.Type != MsgRouteAdd {
		return nil, fmt.Errorf("%w: got %s, want RouteAdd", ErrTypeMismatch, msg.Type)
	}
	var p RoutePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal route add: %w", err)
	}
	return &p, nil
}

// EncodeRouteRemove creates a RouteRemove message from the given payload.
func EncodeRouteRemove(p *RoutePayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal route remove: %w", err)
	}
	return &Message{Type: MsgRouteRemove, Payload: data}, nil
}

// DecodeRouteRemove extracts a RoutePayload from a RouteRemove message.
func DecodeRouteRemove(msg *Message) (*RoutePayload, error) {
	if msg.Type != MsgRouteRemove {
		return nil, fmt.Errorf("%w: got %s, want RouteRemove", ErrTypeMismatch, msg.Type)
	}
	var p RoutePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal route remove: %w", err)
	}
	return &p, nil
}

// EncodeListenerRequest creates a ListenerRequest message from the given payload.
func EncodeListenerRequest(p *ListenerRequestPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal listener request: %w", err)
	}
	return &Message{Type: MsgListenerRequest, Payload: data}, nil
}

// DecodeListenerRequest extracts a ListenerRequestPayload from a message.
func DecodeListenerRequest(msg *Message) (*ListenerRequestPayload, error) {
	if msg.Type != MsgListenerRequest {
		return nil, fmt.Errorf("%w: got %s, want ListenerRequest", ErrTypeMismatch, msg.Type)
	}
	var p ListenerRequestPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal listener request: %w", err)
	}
	return &p, nil
}

// EncodeListenerAck creates a ListenerAck message from the given payload.
func EncodeListenerAck(p *ListenerAckPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal listener ack: %w", err)
	}
	return &Message{Type: MsgListenerAck, Payload: data}, nil
}

// DecodeListenerAck extracts a ListenerAckPayload from a message.
func DecodeListenerAck(msg *Message) (*ListenerAckPayload, error) {
	if msg.Type != MsgListenerAck {
		return nil, fmt.Errorf("%w: got %s, want ListenerAck", ErrTypeMismatch, msg.Type)
	}
	var p ListenerAckPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal listener ack: %w", err)
	}
	return &p, nil
}

// NewPing creates a Ping message (empty payload).
func NewPing() *Message {
	return &Message{Type: MsgPing}
}

// NewPong creates a Pong message (empty payload).
func NewPong() *Message {
	return &Message{Type: MsgPong}
}

// NewError creates an Error message with the given string.
func NewError(msg string) *Message {
	return &Message{Type: MsgError, Payload: []byte(msg)}
}

// DecodeError extracts the error string from an Error message.
func DecodeError(msg *Message) (string, error) {
	if msg.Type != MsgError {
		return "", fmt.Errorf("%w: got %s, want Error", ErrTypeMismatch, msg.Type)
	}
	return string(msg.Payload), nil
}

// --- TUN mode payload and helpers ---

// TunStartAckPayload is sent by the agent to confirm or reject TUN mode activation.
type TunStartAckPayload struct {
	Error string `json:"error,omitempty"`
}

// EncodeTunStart creates a TunStart message (empty payload).
func EncodeTunStart() *Message {
	return &Message{Type: MsgTunStart}
}

// EncodeTunStartAck creates a TunStartAck message from the given payload.
func EncodeTunStartAck(p *TunStartAckPayload) (*Message, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal tun start ack: %w", err)
	}
	return &Message{Type: MsgTunStartAck, Payload: data}, nil
}

// DecodeTunStartAck extracts a TunStartAckPayload from a message.
func DecodeTunStartAck(msg *Message) (*TunStartAckPayload, error) {
	if msg.Type != MsgTunStartAck {
		return nil, fmt.Errorf("%w: got %s, want TunStartAck", ErrTypeMismatch, msg.Type)
	}
	var p TunStartAckPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal tun start ack: %w", err)
	}
	return &p, nil
}

// EncodeTunStop creates a TunStop message (empty payload).
func EncodeTunStop() *Message {
	return &Message{Type: MsgTunStop}
}

// packetBufPool pools byte slices for raw packet I/O to reduce GC pressure.
// Buffers are MTU-sized (1500) + headroom; larger packets get fresh allocations.
var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1600)
		return &b
	},
}

// GetPacketBuf returns a pooled byte slice. Caller must call PutPacketBuf when done.
func GetPacketBuf(size int) []byte {
	bp := packetBufPool.Get().(*[]byte)
	b := *bp
	if cap(b) >= size {
		return b[:size]
	}
	// Too small — discard and allocate fresh.
	return make([]byte, size)
}

// PutPacketBuf returns a byte slice to the pool.
func PutPacketBuf(b []byte) {
	if cap(b) < 1600 {
		return // too small to pool, let GC handle it
	}
	b = b[:0]
	packetBufPool.Put(&b)
}

// WriteRawPacket writes a length-prefixed raw IP packet to w.
// Frame format: [length:4 big-endian][data:length]
// The header and data are coalesced into a single write to reduce syscalls.
func WriteRawPacket(w io.Writer, data []byte) error {
	// Coalesce header + data into a single write.
	total := 4 + len(data)
	buf := GetPacketBuf(total)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := w.Write(buf[:total])
	PutPacketBuf(buf)
	if err != nil {
		return fmt.Errorf("write raw packet: %w", err)
	}
	return nil
}

// ReadRawPacket reads a length-prefixed raw IP packet from r.
// Returns a pooled buffer — caller MUST call PutPacketBuf when done.
func ReadRawPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read raw packet header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	buf := GetPacketBuf(int(length))
	if _, err := io.ReadFull(r, buf); err != nil {
		PutPacketBuf(buf)
		return nil, fmt.Errorf("read raw packet data: %w", err)
	}
	return buf, nil
}
