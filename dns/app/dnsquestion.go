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

func (question *DNSQuestion) Decode(messageBytes []byte, offset int) int {
	name, offsetName := nameExtract(messageBytes, offset)
	offset += offsetName
	question.Name = name

	//TODO: this logic currently required specific order and can be error prone
	question.Type, offset = ReadUint16(messageBytes, offset)
	question.Class, offset = ReadUint16(messageBytes, offset)

	return offset
}
