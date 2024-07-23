package main

import (
	"bytes"
	"encoding/binary"
)

type DNSAnswer struct {
	Name   []byte
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

func (answer *DNSAnswer) Encode() ([]byte, error) {

	buf := new(bytes.Buffer)

	buf.Write(answer.Name)
	if err := binary.Write(buf, binary.BigEndian, answer.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, answer.Class); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, answer.TTL); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, answer.Length); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, answer.Data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (answer *DNSAnswer) Decode(messageBytes []byte, offset int) int {
	name, offsetName := nameExtract(messageBytes, offset)
	offset += offsetName
	answer.Name = name

	answer.Type = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
	offset += 2

	answer.Class = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
	offset += 2

	answer.TTL = binary.BigEndian.Uint32(messageBytes[offset : offset+4])
	offset += 4

	answer.Length = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
	offset += 2

	answer.Data = messageBytes[offset : offset+4]
	offset += 4

	return offset
}
