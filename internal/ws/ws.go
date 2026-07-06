package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const maxFramePayload = 16 * 1024 * 1024

type Conn struct {
	conn        net.Conn
	r           *bufio.Reader
	mu          sync.Mutex
	fragOpcode  byte
	fragPayload []byte
}

func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("missing websocket upgrade")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("missing websocket connection upgrade")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errors.New("unsupported websocket version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if !validWebSocketKey(key) {
		return nil, errors.New("invalid websocket key")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response writer does not support hijack")
	}
	netConn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + websocketAccept(key) + "\r\n"
	if protocol := acceptedSubprotocol(r.Header.Get("Sec-WebSocket-Protocol")); protocol != "" {
		response += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
	}
	response += "\r\n"
	if _, err := rw.WriteString(response); err != nil {
		_ = netConn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = netConn.Close()
		return nil, err
	}
	return &Conn{conn: netConn, r: rw.Reader}, nil
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func validWebSocketKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decoded) == 16
}

func acceptedSubprotocol(header string) string {
	for _, protocol := range strings.Split(header, ",") {
		protocol = strings.TrimSpace(protocol)
		if protocol == "guacamole" {
			return protocol
		}
	}
	return ""
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) SendJSON(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.SendText(raw)
}

func (c *Conn) SendText(raw []byte) error {
	return c.writeFrame(1, raw)
}

func (c *Conn) SendBinary(raw []byte) error {
	return c.writeFrame(2, raw)
}

func (c *Conn) SendPong(raw []byte) error {
	if len(raw) > 125 {
		raw = raw[:125]
	}
	return c.writeFrame(10, raw)
}

func (c *Conn) ReadJSON(v any) error {
	for {
		op, payload, err := c.ReadFrame()
		if err != nil {
			return err
		}
		switch op {
		case 1, 2:
			return json.Unmarshal(payload, v)
		case 8:
			return io.EOF
		case 9:
			_ = c.writeFrame(10, payload)
		}
	}
}

func (c *Conn) ReadFrame() (byte, []byte, error) {
	for {
		opcode, fin, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}

		switch {
		case opcode == 0:
			if c.fragOpcode == 0 {
				return 0, nil, errors.New("websocket continuation frame without fragmented message")
			}
			if err := c.appendFragment(payload); err != nil {
				return 0, nil, err
			}
			if fin {
				op, complete := c.fragOpcode, c.fragPayload
				c.fragOpcode = 0
				c.fragPayload = nil
				return op, complete, nil
			}
		case opcode == 1 || opcode == 2:
			if c.fragOpcode != 0 {
				return 0, nil, errors.New("websocket data frame received before fragmented message completed")
			}
			if fin {
				return opcode, payload, nil
			}
			c.fragOpcode = opcode
			c.fragPayload = append(c.fragPayload[:0], payload...)
		case opcode >= 8:
			return opcode, payload, nil
		default:
			return 0, nil, fmt.Errorf("unsupported websocket opcode: %d", opcode)
		}
	}
}

func (c *Conn) readFrame() (byte, bool, []byte, error) {
	first, err := c.r.ReadByte()
	if err != nil {
		return 0, false, nil, err
	}
	second, err := c.r.ReadByte()
	if err != nil {
		return 0, false, nil, err
	}

	fin := first&0x80 != 0
	if first&0x70 != 0 {
		return 0, false, nil, errors.New("websocket reserved bits are not supported")
	}
	opcode := first & 0x0f
	masked := second&0x80 != 0
	length := uint64(second & 0x7f)
	if !masked {
		return 0, false, nil, errors.New("client websocket frames must be masked")
	}
	if opcode >= 8 && !fin {
		return 0, false, nil, errors.New("websocket control frames must not be fragmented")
	}
	if opcode >= 8 && length > 125 {
		return 0, false, nil, errors.New("websocket control frame too large")
	}

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return 0, false, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return 0, false, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxFramePayload {
		return 0, false, nil, fmt.Errorf("websocket frame too large: %d", length)
	}
	if opcode >= 8 && length > 125 {
		return 0, false, nil, errors.New("websocket control frame too large")
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.r, mask[:]); err != nil {
			return 0, false, nil, err
		}
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, false, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, fin, payload, nil
}

func (c *Conn) appendFragment(payload []byte) error {
	if len(c.fragPayload)+len(payload) > maxFramePayload {
		return fmt.Errorf("websocket fragmented message too large: %d", len(c.fragPayload)+len(payload))
	}
	c.fragPayload = append(c.fragPayload, payload...)
	return nil
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := []byte{0x80 | opcode}
	length := len(payload)
	switch {
	case length < 126:
		header = append(header, byte(length))
	case length <= 0xffff:
		header = append(header, 126, byte(length>>8), byte(length))
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		header = append(header, ext[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}
