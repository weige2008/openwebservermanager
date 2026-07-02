package guac

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Instruction struct {
	Opcode string
	Args   []string
}

func Encode(opcode string, args ...string) []byte {
	parts := append([]string{opcode}, args...)
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte('.')
		b.WriteString(part)
	}
	b.WriteByte(';')
	return []byte(b.String())
}

func ReadInstruction(reader *bufio.Reader) (Instruction, []byte, error) {
	var raw strings.Builder
	values := []string{}

	for {
		lengthText, err := readUntil(reader, '.')
		if err != nil {
			return Instruction{}, nil, err
		}
		raw.WriteString(lengthText)
		raw.WriteByte('.')
		length, err := strconv.Atoi(lengthText)
		if err != nil {
			return Instruction{}, nil, fmt.Errorf("invalid guacamole length %q: %w", lengthText, err)
		}
		if length < 0 || length > 1024*1024 {
			return Instruction{}, nil, fmt.Errorf("invalid guacamole element length %d", length)
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return Instruction{}, nil, err
		}
		raw.Write(buf)
		values = append(values, string(buf))

		delimiter, err := reader.ReadByte()
		if err != nil {
			return Instruction{}, nil, err
		}
		raw.WriteByte(delimiter)
		if delimiter == ';' {
			break
		}
		if delimiter != ',' {
			return Instruction{}, nil, fmt.Errorf("invalid guacamole delimiter %q", delimiter)
		}
	}

	if len(values) == 0 {
		return Instruction{}, nil, fmt.Errorf("empty guacamole instruction")
	}
	return Instruction{Opcode: values[0], Args: values[1:]}, []byte(raw.String()), nil
}

func readUntil(reader *bufio.Reader, delimiter byte) (string, error) {
	var b strings.Builder
	for {
		ch, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if ch == delimiter {
			return b.String(), nil
		}
		b.WriteByte(ch)
		if b.Len() > 16 {
			return "", fmt.Errorf("guacamole length prefix too long")
		}
	}
}