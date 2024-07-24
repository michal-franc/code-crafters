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

// Answer has dynamic sized fields like Name which require to read it step by step
func (answer *DNSAnswer) Decode(messageBytes []byte, offset int) int {
	name, offsetName := nameExtract(messageBytes, offset)
	offset += offsetName
	answer.Name = name

	//TODO: this logic currently required specific order and can be error prone
	answer.Type, offset = ReadUint16(messageBytes, offset)
	answer.Class, offset = ReadUint16(messageBytes, offset)
	answer.TTL, offset = ReadUint32(messageBytes, offset)
	answer.Length, offset = ReadUint16(messageBytes, offset)

	answer.Data = messageBytes[offset : offset+4]
	offset += 4

	return offset
}
