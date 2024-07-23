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
