package ws

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestValidWebSocketKey(t *testing.T) {
	if !validWebSocketKey("dGhlIHNhbXBsZSBub25jZQ==") {
		t.Fatal("expected RFC sample key to be valid")
	}
	if validWebSocketKey("not-base64") {
		t.Fatal("expected malformed key to be invalid")
	}
	if validWebSocketKey("c2hvcnQ=") {
		t.Fatal("expected short key to be invalid")
	}
}

func TestReadFrameSupportsFragmentedText(t *testing.T) {
	conn := newReadOnlyConn(
		clientFrame(false, 1, []byte("hello ")),
		clientFrame(true, 0, []byte("world")),
	)

	opcode, payload, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("read fragmented frame: %v", err)
	}
	if opcode != 1 || string(payload) != "hello world" {
		t.Fatalf("fragmented frame = opcode %d payload %q", opcode, payload)
	}
}

func TestReadFrameReturnsControlDuringFragment(t *testing.T) {
	conn := newReadOnlyConn(
		clientFrame(false, 1, []byte("hello ")),
		clientFrame(true, 9, []byte("ping")),
		clientFrame(true, 0, []byte("world")),
	)

	opcode, payload, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("read ping during fragment: %v", err)
	}
	if opcode != 9 || string(payload) != "ping" {
		t.Fatalf("control frame = opcode %d payload %q", opcode, payload)
	}

	opcode, payload, err = conn.ReadFrame()
	if err != nil {
		t.Fatalf("read resumed fragmented frame: %v", err)
	}
	if opcode != 1 || string(payload) != "hello world" {
		t.Fatalf("resumed fragmented frame = opcode %d payload %q", opcode, payload)
	}
}

func TestReadFrameRejectsUnexpectedContinuation(t *testing.T) {
	conn := newReadOnlyConn(clientFrame(true, 0, []byte("orphan")))

	_, _, err := conn.ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "continuation") {
		t.Fatalf("unexpected continuation error = %v", err)
	}
}

func TestReadFrameRejectsInterleavedDataFrame(t *testing.T) {
	conn := newReadOnlyConn(
		clientFrame(false, 1, []byte("hello")),
		clientFrame(true, 2, []byte("binary")),
	)

	_, _, err := conn.ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "before fragmented message completed") {
		t.Fatalf("interleaved data frame error = %v", err)
	}
}

func TestReadFrameRejectsFragmentedControlFrame(t *testing.T) {
	conn := newReadOnlyConn(clientFrame(false, 9, []byte("ping")))

	_, _, err := conn.ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "control frames must not be fragmented") {
		t.Fatalf("fragmented control frame error = %v", err)
	}
}

func newReadOnlyConn(frames ...[]byte) *Conn {
	return &Conn{r: bufio.NewReader(bytes.NewReader(bytes.Join(frames, nil)))}
}

func clientFrame(fin bool, opcode byte, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	frame := []byte{first, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for i, value := range payload {
		frame = append(frame, value^mask[i%len(mask)])
	}
	return frame
}
