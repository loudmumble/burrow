package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// IPv4 protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// IPv4 header constants.
const (
	ipv4MinHeaderLen = 20
	ipv4VersionIHL   = 0  // offset of Version + IHL byte
	ipv4TotalLen     = 2  // offset of Total Length field
	ipv4Protocol     = 9  // offset of Protocol field
	ipv4SrcIP        = 12 // offset of Source IP
	ipv4DstIP        = 16 // offset of Destination IP
)

var (
	// ErrPacketTooShort is returned when a packet is shorter than the minimum IPv4 header.
	ErrPacketTooShort = errors.New("tun: packet too short for IPv4 header")

	// ErrNotIPv4 is returned when the version nibble is not 4.
	ErrNotIPv4 = errors.New("tun: not an IPv4 packet")
)

// IPPacket holds parsed fields from an IPv4 header, sufficient for
// making routing decisions without parsing the full packet.
type IPPacket struct {
	// Version is the IP version (always 4 for IPv4).
	Version uint8

	// SrcIP is the source IP address.
	SrcIP net.IP

	// DstIP is the destination IP address.
	DstIP net.IP

	// Protocol is the IP protocol number (e.g., 6=TCP, 17=UDP, 1=ICMP).
	Protocol uint8

	// PayloadLen is the total packet length minus the header length.
	PayloadLen int
}

// ParseIPHeader parses the first 20 bytes of an IPv4 header and returns
// the key fields needed for routing decisions.
func ParseIPHeader(raw []byte) (*IPPacket, error) {
	if len(raw) < ipv4MinHeaderLen {
		return nil, ErrPacketTooShort
	}

	version := raw[ipv4VersionIHL] >> 4
	if version != 4 {
		return nil, fmt.Errorf("%w: version=%d", ErrNotIPv4, version)
	}

	ihl := int(raw[ipv4VersionIHL]&0x0F) * 4 // header length in bytes
	totalLen := int(binary.BigEndian.Uint16(raw[ipv4TotalLen:]))

	payloadLen := totalLen - ihl
	if payloadLen < 0 {
		payloadLen = 0
	}

	return &IPPacket{
		Version:    version,
		SrcIP:      net.IP(raw[ipv4SrcIP : ipv4SrcIP+4]).To4(),
		DstIP:      net.IP(raw[ipv4DstIP : ipv4DstIP+4]).To4(),
		Protocol:   raw[ipv4Protocol],
		PayloadLen: payloadLen,
	}, nil
}

// IsIPv4 returns true if the first nibble of raw indicates an IPv4 packet (version 4).
func IsIPv4(raw []byte) bool {
	if len(raw) < 1 {
		return false
	}
	return (raw[0] >> 4) == 4
}
