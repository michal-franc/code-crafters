package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNameEncoder(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"www.example.com", []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"com", []byte{3, 'c', 'o', 'm', 0}},
		{"", []byte{0}},
		{"a.b.c", []byte{1, 'a', 1, 'b', 1, 'c', 0}},
		{"sub.domain.example.com", []byte{3, 's', 'u', 'b', 6, 'd', 'o', 'm', 'a', 'i', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
	}

	for _, test := range tests {
		result := nameEncoder(test.input)
		assert.Equal(t, test.expected, result, "For input %q, expected %v, but got %v", test.input, test.expected, result)
	}
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

	result, err := ipV4Encoder(given)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, expected, result)
}

func TestDecodeDNSMessage(t *testing.T) {

	nameEncoded := nameEncoder("google.com")
	ipEncoded, err := ipV4Encoder("8.8.8.8")
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

	testMessageEncoded, err := testMessage.Encode()
	if err != nil {
		fmt.Println("Failed to encode response:", err)
	}

	result := DNSMessage{}
	err = result.Decode(testMessageEncoded)
	if err != nil {
		t.Error("failed to decode the message:", err)
	}

	assert.Equal(t, testMessage.Header, result.Header)
	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result.Answers))
	assert.Equal(t, 2, len(result.Questions))
	assert.Equal(t, testMessage, result)
}

func TestDoesWordHasAPointer(t *testing.T) {
	tests := []struct {
		word     []byte
		expected bool
	}{
		{[]byte{0xC0, 0x00}, true},  // 1100 0000 0000 0000 - Both bits 15 and 14 are set
		{[]byte{0x80, 0x00}, false}, // 1000 0000 0000 0000 - Only bit 15 is set
		{[]byte{0x40, 0x00}, false}, // 0100 0000 0000 0000 - Only bit 14 is set
		{[]byte{0x00, 0x00}, false}, // 0000 0000 0000 0000 - Neither bit 15 nor 14 is set
		{[]byte{0xC0, 0x01}, true},  // 1100 0000 0000 0001 - Both bits 15 and 14 are set
	}

	for _, test := range tests {
		result := doesWordHasAPointer(test.word)
		assert.Equal(t, test.expected, result, "For word %v, expected %v, but got %v --- binary test value - %b", test.word, test.expected, result, test.word)
	}
}

func TestExtractPointer(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{[]byte{0xC0, 0x00}, 0},  // 1100 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
		{[]byte{0xC0, 0x01}, 1},  // 1100 0000 0000 0001 - after clearing pointer bits -> 0000 0000 0000 0001
		{[]byte{0xC0, 0x10}, 16}, // 1100 0000 0001 0000 - after clearing pointer bits -> 0000 0000 0001 0000
		{[]byte{0x00, 0x00}, 0},  // 0000 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
		// the top bits are cleared and there shouldn't be any value returned
		{[]byte{0x80, 0x00}, 0}, // 1000 0000 0000 0000 - after clearing pointer bits -> 1000 0000 0000 0000
		{[]byte{0x40, 0x00}, 0}, // 0100 0000 0000 0000 - after clearing pointer bits -> 0100 0000 0000 0000
	}

	for _, test := range tests {
		result := extractPointer(test.input)
		assert.Equal(t, test.expected, result, "For input %v, expected %d, but got %d", test.input, test.expected, result)
	}
}
