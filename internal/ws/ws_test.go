package ws

import "testing"

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
