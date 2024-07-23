package main

import (
	"bytes"
	"encoding/binary"
)

type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

func (question *DNSQuestion) Encode() ([]byte, error) {

	buf := new(bytes.Buffer)

	buf.Write(question.Name)
	if err := binary.Write(buf, binary.BigEndian, question.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, question.Class); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (q *DNSQuestion) Decode(messageBytes []byte, offset int) int {
	name, offsetName := nameExtract(messageBytes, offset)
	offset += offsetName
	q.Name = name

	q.Type = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
	offset += 2

	q.Class = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
	offset += 2

	return offset
}
