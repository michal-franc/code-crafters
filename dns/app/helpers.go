package main

import "encoding/binary"

func ReadUint16(data []byte, offset int) (uint16, int) {
	uint16ByteSize := 2

	v := binary.BigEndian.Uint16(data[offset : offset+uint16ByteSize])
	offset += uint16ByteSize

	return v, offset
}

func ReadUint32(data []byte, offset int) (uint32, int) {
	uint32ByteSize := 4

	v := binary.BigEndian.Uint32(data[offset : offset+uint32ByteSize])
	offset += uint32ByteSize

	return v, offset
}
