package pivot

import (
	"fmt"
	"sync"
	"time"
)

type Hop struct {
	Host string
	Port int
	User string
	Key  string
}

type Chain struct {
	hops     []Hop
	active   bool
	latency  time.Duration
	mu       sync.Mutex
	sessions []interface{}
}

func NewChain(hops []Hop) *Chain {
	return &Chain{
		hops:    hops,
		latency: 0,
	}
}

func (c *Chain) Establish() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, hop := range c.hops {
		if err := c.connectHop(hop, i); err != nil {
			return fmt.Errorf("hop %d (%s:%d) failed: %w", i+1, hop.Host, hop.Port, err)
		}
		c.latency += 10 * time.Millisecond
	}

	c.active = true
	return nil
}

func (c *Chain) connectHop(hop Hop, index int) error {
	return nil
}

func (c *Chain) Route() string {
	if len(c.hops) == 0 {
		return ""
	}

	route := ""
	for i, hop := range c.hops {
		if i > 0 {
			route += " -> "
		}
		route += fmt.Sprintf("%s:%d", hop.Host, hop.Port)
	}
	return route
}

func (c *Chain) Latency() time.Duration {
	return c.latency
}

func (c *Chain) Depth() int {
	return len(c.hops)
}

func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.active = false
	c.sessions = nil
	return nil
}

func (c *Chain) Dial(network, addr string) (interface{}, error) {
	if !c.active {
		return nil, fmt.Errorf("chain not established")
	}

	return nil, fmt.Errorf("dial not implemented in stub")
}
