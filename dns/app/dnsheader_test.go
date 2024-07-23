package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// given struct of dns msg
// create a binary representation used by dns
func TestHeaderWithIDEncoding(t *testing.T) {

	header := DNSHeader{
		ID: 1,
	}

	encodedHeader, err := header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// as ID is 1 it only occupies 2nd byte in the byte array
	assert.Equal(t, encodedHeader, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Header with ID %d not encoded correctly", header.ID)

	header = DNSHeader{
		ID: 16,
	}

	encodedHeader, err = header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// as ID is 1 it only occupies 2nd byte in the byte array
	assert.Equal(t, encodedHeader, []byte{0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Header with ID %d not encoded correctly", header.ID)

	header = DNSHeader{
		ID: 257,
	}

	encodedHeader, err = header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// 257 -> 256 + 1  in 2 bytes
	// 256 in upper byte is 1 as its the 9th bit
	// 1 is lower byte is 1
	assert.Equal(t, encodedHeader, []byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Header with ID %d not encoded correctly", header.ID)
}

func TestEmptyHeaderEncoding(t *testing.T) {

	header := DNSHeader{}

	encodedHeader, err := header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// as ID is 1 it only occupies 2nd byte in the byte array
	assert.Equal(t, encodedHeader, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestHeaderWithFlagsEncoding(t *testing.T) {

	header := DNSHeader{}

	err := header.FLAGS.SetRcode(1)
	assert.NoError(t, err)

	encodedHeader, err := header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// flags occupy 3rd and 4th byte
	// RCode is the last flag in the flags - so setting it to 1 will lead to value being one in the 4th byte
	assert.Equal(t, encodedHeader, []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, "Header with RCode not encoded correctly")

	header = DNSHeader{}

	header.FLAGS.SetRD(true)

	encodedHeader, err = header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// flags occupy 3rd and 4th byte
	// Rd is the last bit in the 3rd byte
	assert.Equal(t, encodedHeader, []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Header with RD not encoded correctly")
}

func TestHeaderWithQDCountEncoding(t *testing.T) {

	header := DNSHeader{
		QDCOUNT: 10,
	}

	encodedHeader, err := header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// QD Count occupies 5th and 6th bit
	assert.Equal(t, encodedHeader, []byte{0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0, 0, 0}, "Header with QDCount not encoded correctly")
}

func TestHeaderWithANCountEncoding(t *testing.T) {

	header := DNSHeader{
		ANCOUNT: 10,
	}

	encodedHeader, err := header.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// QD Count occupies 5th and 6th bit
	assert.Equal(t, encodedHeader, []byte{0, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0}, "Header with ANCount not encoded correctly")
}
