package guac

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadInstructionRejectsTooManyElements(t *testing.T) {
	var payload strings.Builder
	for i := 0; i < maxInstructionElements+1; i++ {
		if i > 0 {
			payload.WriteByte(',')
		}
		payload.WriteString("1.a")
	}
	payload.WriteByte(';')

	_, _, err := ReadInstruction(bufio.NewReader(strings.NewReader(payload.String())))
	if err == nil {
		t.Fatal("expected too many elements to fail")
	}
}

func TestEncodeAndReadInstructionRoundTrip(t *testing.T) {
	raw := Encode("mouse", "12", "34", "1")
	instruction, _, err := ReadInstruction(bufio.NewReader(strings.NewReader(string(raw))))
	if err != nil {
		t.Fatalf("read instruction: %v", err)
	}
	if instruction.Opcode != "mouse" || len(instruction.Args) != 3 {
		t.Fatalf("unexpected instruction: %#v", instruction)
	}
}
