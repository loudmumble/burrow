package mux

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

// createSessionPair creates a connected client/server Session pair using net.Pipe.
func createSessionPair(t *testing.T) (client *Session, server *Session) {
	t.Helper()

	c1, c2 := net.Pipe()

	var (
		serverSession *Session
		clientSession *Session
		serverErr     error
		clientErr     error
		wg            sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		serverSession, serverErr = NewServerSession(c1)
	}()
	go func() {
		defer wg.Done()
		clientSession, clientErr = NewClientSession(c2)
	}()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("NewServerSession: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("NewClientSession: %v", clientErr)
	}

	t.Cleanup(func() {
		clientSession.Close()
		serverSession.Close()
	})

	return clientSession, serverSession
}

func TestCreateSessionPair(t *testing.T) {
	client, server := createSessionPair(t)

	if client.IsClosed() {
		t.Error("client session should not be closed")
	}
	if server.IsClosed() {
		t.Error("server session should not be closed")
	}
	if client.NumStreams() != 0 {
		t.Errorf("client NumStreams = %d, want 0", client.NumStreams())
	}
	if server.NumStreams() != 0 {
		t.Errorf("server NumStreams = %d, want 0", server.NumStreams())
	}
}

func TestOpenAcceptStream(t *testing.T) {
	client, server := createSessionPair(t)

	// Client opens a stream, server accepts it.
	var (
		serverConn net.Conn
		acceptErr  error
		wg         sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, acceptErr = server.Accept()
	}()

	clientConn, err := client.Open()
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("server.Accept: %v", acceptErr)
	}

	defer clientConn.Close()
	defer serverConn.Close()

	if client.NumStreams() != 1 {
		t.Errorf("client NumStreams = %d, want 1", client.NumStreams())
	}
	if server.NumStreams() != 1 {
		t.Errorf("server NumStreams = %d, want 1", server.NumStreams())
	}
}

func TestBidirectionalData(t *testing.T) {
	client, server := createSessionPair(t)

	var (
		serverConn net.Conn
		acceptErr  error
		wg         sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, acceptErr = server.Accept()
	}()

	clientConn, err := client.Open()
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("server.Accept: %v", acceptErr)
	}

	defer clientConn.Close()
	defer serverConn.Close()

	// Client -> Server
	clientMsg := []byte("hello from client")
	_, err = clientConn.Write(clientMsg)
	if err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != string(clientMsg) {
		t.Errorf("server got %q, want %q", buf[:n], clientMsg)
	}

	// Server -> Client
	serverMsg := []byte("hello from server")
	_, err = serverConn.Write(serverMsg)
	if err != nil {
		t.Fatalf("server write: %v", err)
	}

	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(serverMsg) {
		t.Errorf("client got %q, want %q", buf[:n], serverMsg)
	}
}

func TestMultipleConcurrentStreams(t *testing.T) {
	client, server := createSessionPair(t)

	const numStreams = 10
	msg := []byte("stream data")
	var wg sync.WaitGroup

	// Server: accept streams and read-then-write-back fixed-length data.
	wg.Add(numStreams)
	go func() {
		for i := 0; i < numStreams; i++ {
			conn, err := server.Accept()
			if err != nil {
				t.Errorf("server.Accept stream %d: %v", i, err)
				return
			}
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				c.Write(buf)
			}(conn)
		}
	}()

	// Client: open streams concurrently, send data, verify echo.
	errs := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := client.Open()
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()

			if _, err := conn.Write(msg); err != nil {
				errs <- err
				return
			}

			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- err
				return
			}
			if string(buf) != string(msg) {
				errs <- fmt.Errorf("got %q, want %q", buf, msg)
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("stream error: %v", err)
		}
	}
}

func TestCloseHandling(t *testing.T) {
	client, server := createSessionPair(t)

	// Open a stream to ensure the session is active.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.Accept()
	}()

	conn, err := client.Open()
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	wg.Wait()
	conn.Close()

	// Close client session.
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close: %v", err)
	}
	if !client.IsClosed() {
		t.Error("client should be closed after Close()")
	}

	// Opening a stream on a closed session should fail.
	_, err = client.Open()
	if err == nil {
		t.Error("Open on closed session should return error")
	}
}

func TestCloseServerSession(t *testing.T) {
	client, server := createSessionPair(t)

	if err := server.Close(); err != nil {
		t.Fatalf("server.Close: %v", err)
	}
	if !server.IsClosed() {
		t.Error("server should be closed after Close()")
	}

	// Accept on a closed session should fail.
	_, err := server.Accept()
	if err == nil {
		t.Error("Accept on closed session should return error")
	}

	// Client operations should also fail after server closes.
	_, err = client.Open()
	if err == nil {
		t.Error("Open should fail when remote session is closed")
	}
}
