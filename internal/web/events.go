// Package web provides an embedded HTTP dashboard and REST API for Burrow.
package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// EventType identifies the kind of dashboard event.
type EventType string

const (
	EventSessionConnect    EventType = "session.connect"
	EventSessionDisconnect EventType = "session.disconnect"
	EventTunnelStart       EventType = "tunnel.start"
	EventTunnelStop        EventType = "tunnel.stop"
	EventTunnelError       EventType = "tunnel.error"
	EventRouteAdd          EventType = "route.add"
	EventRouteRemove       EventType = "route.remove"
	EventStats             EventType = "stats"
)

// Event is a single dashboard event sent over SSE.
type Event struct {
	Type EventType   `json:"type"`
	Data interface{} `json:"data"`
}

// subscriberBufSize is the channel buffer for each SSE subscriber.
const subscriberBufSize = 64

// EventBus fans out events to all connected SSE subscribers.
type EventBus struct {
	subscribers map[chan Event]struct{}
	mu          sync.RWMutex
}

// NewEventBus creates a ready-to-use EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan Event]struct{}),
	}
}

// Subscribe returns a buffered channel that receives all published events.
// The caller must call Unsubscribe when done.
func (eb *EventBus) Subscribe() chan Event {
	ch := make(chan Event, subscriberBufSize)
	eb.mu.Lock()
	eb.subscribers[ch] = struct{}{}
	eb.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes the subscriber channel.
func (eb *EventBus) Unsubscribe(ch chan Event) {
	eb.mu.Lock()
	delete(eb.subscribers, ch)
	eb.mu.Unlock()
	close(ch)
}

// Publish sends an event to every subscriber. If a subscriber's buffer is
// full the event is dropped for that subscriber (non-blocking).
func (eb *EventBus) Publish(evt Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for ch := range eb.subscribers {
		select {
		case ch <- evt:
		default:
			// subscriber too slow, drop
		}
	}
}

// ServeHTTP implements http.Handler for SSE streaming.
// It sets the required headers and writes newline-delimited JSON events
// in the standard SSE format: "data: {json}\n\n".
func (eb *EventBus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := eb.Subscribe()
	defer eb.Unsubscribe(ch)

	// Write an initial comment to flush headers.
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
