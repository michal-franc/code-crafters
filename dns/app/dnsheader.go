package main

import (
	"bytes"
	"encoding/binary"
)

type DNSHeader struct {
	ID      uint16
	FLAGS   Flags
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (h *DNSHeader) Encode() ([]byte, error) {

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
