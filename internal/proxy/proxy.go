package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

type SOCKS5 struct {
	addr     string
	port     int
	username string
	password string
	ln       net.Listener
	running  bool
	mu       sync.Mutex
}

func NewSOCKS5(addr string, port int, username, password string) *SOCKS5 {
	return &SOCKS5{
		addr:     addr,
		port:     port,
		username: username,
		password: password,
	}
}

func (s *SOCKS5) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.addr, s.port))
	if err != nil {
		return err
	}
	s.ln = ln
	s.running = true

	go s.accept()
	return nil
}

func (s *SOCKS5) accept() {
	for s.running {
		conn, err := s.ln.Accept()
		if err != nil {
			continue
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5) handle(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)

	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	if buf[0] != 0x05 {
		conn.Write([]byte{0x05, 0x01})
		return
	}

	if s.username != "" {
		conn.Write([]byte{0x05, 0x02})

		n, err = conn.Read(buf)
		if err != nil || n < 2 || buf[0] != 0x01 {
			return
		}

		ulen := int(buf[1])
		if n < 2+ulen+1 {
			return
		}
		username := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		if n < 2+ulen+1+plen {
			return
		}
		password := string(buf[3+ulen : 3+ulen+plen])

		if username != s.username || password != s.password {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 {
		return
	}

	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	switch buf[3] {
	case 0x01:
		if n < 10 {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			binary.BigEndian.Uint16(buf[8:10]))
	case 0x03:
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		domain := string(buf[5 : 5+dlen])
		port := binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
		target = fmt.Sprintf("%s:%d", domain, port)
	case 0x04:
		if n < 22 {
			return
		}
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			binary.BigEndian.Uint16(buf[4:6]),
			binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]),
			binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]),
			binary.BigEndian.Uint16(buf[14:16]),
			binary.BigEndian.Uint16(buf[16:18]),
			binary.BigEndian.Uint16(buf[18:20]),
			binary.BigEndian.Uint16(buf[20:22]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	resp := make([]byte, 10)
	resp[0] = 0x05
	resp[1] = 0x00
	resp[2] = 0x00
	resp[3] = 0x01
	copy(resp[4:8], localAddr.IP.To4())
	binary.BigEndian.PutUint16(resp[8:10], uint16(localAddr.Port))
	conn.Write(resp)

	go s.relay(conn, targetConn)
	s.relay(targetConn, conn)
}

func (s *SOCKS5) relay(dst io.Writer, src io.Reader) {
	io.Copy(dst, src)
}

func (s *SOCKS5) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	if s.ln != nil {
		s.ln.Close()
	}
}
