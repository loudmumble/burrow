// Package replay provides session traffic recording and playback for
// debugging, engagement reporting, and training.
//
// Traffic is recorded as a sequence of timestamped frames in a binary
// format: [timestamp_ns:8][direction:1][length:4][data:length]
package replay

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Direction indicates the traffic direction.
type Direction byte

const (
	DirInbound  Direction = 0x00 // agent → server
	DirOutbound Direction = 0x01 // server → agent
)

// Frame is a single recorded traffic frame.
type Frame struct {
	Timestamp time.Time
	Direction Direction
	Data      []byte
}

// Recorder writes traffic frames to a file.
type Recorder struct {
	f     *os.File
	mu    sync.Mutex
	start time.Time
}

// NewRecorder creates a recorder that writes to the given path.
func NewRecorder(path string) (*Recorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create replay file: %w", err)
	}
	// Write magic header.
	f.Write([]byte("BRPL")) // Burrow Replay
	return &Recorder{f: f, start: time.Now()}, nil
}

// Record writes a traffic frame.
func (r *Recorder) Record(dir Direction, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ts := time.Now().UnixNano()
	header := make([]byte, 13) // 8 timestamp + 1 direction + 4 length
	binary.BigEndian.PutUint64(header[0:8], uint64(ts))
	header[8] = byte(dir)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(data)))

	if _, err := r.f.Write(header); err != nil {
		return err
	}
	if _, err := r.f.Write(data); err != nil {
		return err
	}
	return nil
}

// Close closes the recorder.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Player reads traffic frames from a replay file.
type Player struct {
	f *os.File
}

// NewPlayer opens a replay file for playback.
func NewPlayer(path string) (*Player, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open replay file: %w", err)
	}
	// Read and verify magic.
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		f.Close()
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != "BRPL" {
		f.Close()
		return nil, fmt.Errorf("invalid replay file (bad magic)")
	}
	return &Player{f: f}, nil
}

// Next reads the next frame from the replay. Returns io.EOF at end.
func (p *Player) Next() (*Frame, error) {
	header := make([]byte, 13)
	if _, err := io.ReadFull(p.f, header); err != nil {
		return nil, err
	}

	ts := int64(binary.BigEndian.Uint64(header[0:8]))
	dir := Direction(header[8])
	length := binary.BigEndian.Uint32(header[9:13])

	data := make([]byte, length)
	if _, err := io.ReadFull(p.f, data); err != nil {
		return nil, err
	}

	return &Frame{
		Timestamp: time.Unix(0, ts),
		Direction: dir,
		Data:      data,
	}, nil
}

// ReadAll reads all frames from the replay file.
func (p *Player) ReadAll() ([]*Frame, error) {
	var frames []*Frame
	for {
		f, err := p.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return frames, err
		}
		frames = append(frames, f)
	}
	return frames, nil
}

// Close closes the player.
func (p *Player) Close() error {
	return p.f.Close()
}
