package tftp

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// NewClient creates TFTP client for server on address provided.
func NewClient(addr string) (*Client, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving address %s: %v", addr, err)
	}
	return &Client{
		addr:      a,
		timeout:   defaultTimeout,
		retries:   defaultRetries,
		localAddr: &net.UDPAddr{},
	}, nil
}

// SetLocalAddr sets the local IP address to use while reaching to remote TFTP endpoint
// Default is kernel choose IP address on it's own
func (c *Client) SetLocalAddr(localaddr string) error {
	if localaddr == "" {
		return fmt.Errorf("localaddr is empty")
	}
	if net.ParseIP(localaddr) == nil {
		return fmt.Errorf("provided localaddr: %s is not valid ip addr", localaddr)
	}
	c.localAddr = &net.UDPAddr{
		IP:   net.ParseIP(localaddr),
		Port: 0,
	}
	return nil
}

// SetTimeout sets maximum time client waits for single network round-trip to succeed.
// Default is 5 seconds.
func (c *Client) SetTimeout(t time.Duration) {
	if t <= 0 {
		c.timeout = defaultTimeout
	}
	c.timeout = t
}

// SetRetries sets maximum number of attempts client made to transmit a packet.
// Default is 5 attempts.
func (c *Client) SetRetries(count int) {
	if count < 1 {
		c.retries = defaultRetries
	}
	c.retries = count
}

// SetBackoff sets a user provided function that is called to provide a
// backoff duration prior to retransmitting an unacknowledged packet.
func (c *Client) SetBackoff(h backoffFunc) {
	c.backoff = h
}

// SetBlockSize sets a custom block size used in the transmission.
func (c *Client) SetBlockSize(s int) {
	c.blksize = s
}

// RequestTSize sets flag to indicate if tsize should be requested.
func (c *Client) RequestTSize(s bool) {
	c.tsize = s
}

// SetDSCP sets the DSCP value to use in the IP header of the UDP packets.
func (c *Client) SetDSCP(dscp int) error {
	if dscp >= 0 && dscp <= 63 {
		c.dscp = dscp
	} else {
		return fmt.Errorf("Invalid DSCP value %d, must be between 0 and 63 inclusive", dscp)
	}
	return nil
}

// Client stores data about a single TFTP client
type Client struct {
	addr      *net.UDPAddr
	timeout   time.Duration
	retries   int
	backoff   backoffFunc
	blksize   int
	tsize     bool
	localAddr *net.UDPAddr
	dscp      int
}

// Send starts outgoing file transmission. It returns io.ReaderFrom or error.
func (c Client) Send(filename string, mode string) (io.ReaderFrom, error) {
	var connected bool
	var conn connConnection
	conn.osconn = &osConn{}
	if err := conn.getUDPConn(&connected, c.localAddr, c.addr, c.dscp, "client"); err != nil {
		return nil, err
	}
	// For client usage we need to set connected to false for all three OS type
	// Windows/Mac/Linux as client socket is not connected to any specific remote address
	connected = false
	s := &sender{
		send:      make([]byte, datagramLength),
		receive:   make([]byte, datagramLength),
		conn:      &conn,
		retry:     &backoff{handler: c.backoff},
		timeout:   c.timeout,
		retries:   c.retries,
		addr:      c.addr,
		mode:      mode,
		connected: connected,
	}
	if c.blksize != 0 {
		s.opts = make(options)
		s.opts["blksize"] = strconv.Itoa(c.blksize)
	}
	n := packRQ(s.send, opWRQ, filename, mode, s.opts)
	addr, err := s.sendWithRetry(n)
	if err != nil {
		return nil, err
	}
	s.addr = addr
	s.opts = nil
	return s, nil
}

// Receive starts incoming file transmission. It returns io.WriterTo or error.
func (c Client) Receive(filename string, mode string) (io.WriterTo, error) {
	var connected bool
	var conn connConnection
	conn.osconn = &osConn{}
	if err := conn.getUDPConn(&connected, c.localAddr, c.addr, c.dscp, "client"); err != nil {
		return nil, err
	}
	// For client usage we need to set connected to false for all three OS type
	// Windows/Mac/Linux as client socket is not connected to any specific remote address
	connected = false
	if c.timeout == 0 {
		c.timeout = defaultTimeout
	}
	r := &receiver{
		send:      make([]byte, datagramLength),
		receive:   make([]byte, datagramLength),
		conn:      &conn,
		retry:     &backoff{handler: c.backoff},
		timeout:   c.timeout,
		retries:   c.retries,
		addr:      c.addr,
		autoTerm:  true,
		block:     1,
		mode:      mode,
		connected: connected,
	}
	if c.blksize != 0 || c.tsize {
		r.opts = make(options)
	}
	if c.blksize != 0 {
		r.opts["blksize"] = strconv.Itoa(c.blksize)
		// Clean it up so we don't send options twice
		defer func() { delete(r.opts, "blksize") }()
	}
	if c.tsize {
		r.opts["tsize"] = "0"
	}
	n := packRQ(r.send, opRRQ, filename, mode, r.opts)
	l, addr, err := r.receiveWithRetry(n)
	if err != nil {
		return nil, err
	}
	r.l = l
	r.addr = addr
	return r, nil
}
