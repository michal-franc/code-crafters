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
