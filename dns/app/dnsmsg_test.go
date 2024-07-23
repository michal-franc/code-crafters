package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// given struct of dns msg
// create a binary representation used by dns
func TestHeaderEncoding(t *testing.T) {

	testMessage := DNSMessage{
		Header: DNSHeader{
			ID: 1234,
		},
	}

	encodedMessage, err := testMessage.encode()

	if err != nil {
		t.Error("Error while encoding DNS", err)
	}

	// example from code crafters
	assert.Equal(t, encodedMessage[0:12], []byte{4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestQuestionNameEncoder(t *testing.T) {
	given := "google.com"
	expected := "\x06google\x03com\x00"

	result := nameEncoder(given)

	assert.Equal(t, expected, string(result))
}

func TestQuestionNameDecoder(t *testing.T) {
	// example from https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
	name1 := "\x01f\x03isi\x04arpa\x00" // not compressed
	// \xc0\x00 == 1100 0000 0000 0000 -> pointing to 0 pointer
	name2 := "\x03foo\xc0\x00"                         // compressed points to pointer
	expectedName2 := "\x03foo\x01f\x03isi\x04arpa\x00" // after decompression
	// \xc0\x06 == 1100 0000 0000 0110 -> pointing to 6 pointer offset
	name3 := "\xc0\x06" // compressed points to pointer only
	expectedName3 := "\x04arpa\x00"

	fullNameBytes := []byte(name1 + name2 + name3)

	result1, offset1 := nameExtract(fullNameBytes, 0)
	result2, offset2 := nameExtract(fullNameBytes, 12)
	result3, offset3 := nameExtract(fullNameBytes, 18)

	assert.Equal(t, name1, string(result1))
	assert.Equal(t, expectedName2, string(result2))
	assert.Equal(t, expectedName3, string(result3))

	// example 1 has full name - so length of name
	assert.Equal(t, 12, offset1)

	// example 2 has compressed name - so comporessed name (4 bytes) + pointer (2 bytes)
	assert.Equal(t, 6, offset2)

	// example 3 has only pointer - so a word so 2 bytes
	assert.Equal(t, 2, offset3)
}

func TestAnswerIpEncoder(t *testing.T) {
	given := "8.8.8.8"
	expected := []byte{0x8, 0x8, 0x8, 0x8}

	result, err := ipEncoder(given)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, expected, result)
}

func TestDecodeDNSMessage(t *testing.T) {

	nameEncoded := nameEncoder("google.com")
	ipEncoded, err := ipEncoder("8.8.8.8")
	if err != nil {
		t.Error("Error while creating encoded ip", err)
	}
	testMessage := DNSMessage{
		Header: DNSHeader{
			ID:      1234,
			QDCOUNT: 2,
			ANCOUNT: 2,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions: []DNSQuestion{
			{
				Name:  nameEncoded,
				Class: 1,
				Type:  1,
			},
			{
				Name:  nameEncoded,
				Class: 1,
				Type:  1,
			},
		},
		Answers: []DNSAnswer{
			{
				Name:   nameEncoded,
				Class:  1,
				Type:   1,
				TTL:    60,
				Length: 4,
				Data:   ipEncoded,
			},
			{
				Name:   nameEncoded,
				Class:  1,
				Type:   1,
				TTL:    60,
				Length: 4,
				Data:   ipEncoded,
			},
		},
	}

	testMessage.Header.FLAGS.SetQR(true)
	testMessage.Header.FLAGS.SetAA(true)
	testMessage.Header.FLAGS.SetRD(true)
	err = testMessage.Header.FLAGS.SetZ(7)
	if err != nil {
		t.Error("Error while setting Z", err)
	}
	err = testMessage.Header.FLAGS.SetRcode(15)
	if err != nil {
		t.Error("Error while setting RCode", err)
	}
	testMessage.Header.FLAGS.SetRA(true)
	err = testMessage.Header.FLAGS.SetOpCode(15)
	if err != nil {
		t.Error("Error while setting OPCode", err)
	}

	testMessageEncoded, err := testMessage.encode()
	if err != nil {
		fmt.Println("Failed to encode response:", err)
	}

	result, err := decodeMessage(testMessageEncoded)
	if err != nil {
		t.Error("failed to decode the message:", err)
	}

	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result.Answers))
	assert.Equal(t, 2, len(result.Questions))
	assert.Equal(t, testMessage, result)
}
