package main

import (
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

// Tests for ipV4Encoder function
func TestIpV4Encoder(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
		err      bool
	}{
		{"192.168.1.1", []byte{192, 168, 1, 1}, false},
		{"255.255.255.255", []byte{255, 255, 255, 255}, false},
		{"0.0.0.0", []byte{0, 0, 0, 0}, false},
		{"10.0.0.1", []byte{10, 0, 0, 1}, false},
		{"256.100.50.25", nil, true}, // Value out of range
		{"192.168.1", nil, true},     // Not enough parts
		{"192.168.1.1.1", nil, true}, // Too many parts
		{"192.168.1.a", nil, true},   // Non-numeric part
		{"192.-1.1.1", nil, true},    // Negative value
		{"192.168.1.300", nil, true}, // Out of range part
	}

	for _, test := range tests {
		result, err := ipV4Encoder(test.input)
		if test.err {
			assert.Error(t, err, "For input %q, expected error: %v, but got: %v", test.input, test.err, err)
		} else {
			assert.NoError(t, err)
		}

		assert.Equal(t, test.expected, result, "For input %q, expected %v, but got %v", test.input, test.expected, result)
	}
}

func TestNameExtract(t *testing.T) {
	// we  have 3 names here
	// f.isi.arpa
	// foo.f.isi.arpa
	// arpa
	data := []byte{0x01, 'f', 0x03, 'i', 's', 'i', 0x04, 'a', 'r', 'p', 'a', 0x00, 0x03, 'f', 'o', 'o', 0xc0, 0x00, 0xc0, 0x06}

	tests := []struct {
		expected []byte
	}{
		{[]byte{0x01, 'f', 0x03, 'i', 's', 'i', 0x04, 'a', 'r', 'p', 'a', 0x00}},
		{[]byte{0x03, 'f', 'o', 'o', 0x01, 'f', 0x03, 'i', 's', 'i', 0x04, 'a', 'r', 'p', 'a', 0x00}},
		{[]byte{0x04, 'a', 'r', 'p', 'a', 0x00}},
	}

	startOffset := 0
	var result []byte
	var err error

	// This test assumes that tests struct order is stable
	for _, test := range tests {
		result, startOffset, err = nameExtract(data, startOffset)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, result)
	}
}

// This is a test to verify if the logic will break with error and not let the infinite loop
// 100 pointers assumed ass too much and indication that someone is trying to DDOS us
func TestNameExtractWith100Pointers(t *testing.T) {

	// special name that will lead to infinite loop
	testData := []byte{0xc0, 0x00, 0xc0}

	_, _, err := nameExtract(testData, 0)
	assert.Error(t, err)
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
		t.Error("Failed to encode response:", err)
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

func TestExtractPointer(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{[]byte{0xC0, 0x00}, 0},  // 1100 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
		{[]byte{0xC0, 0x01}, 1},  // 1100 0000 0000 0001 - after clearing pointer bits -> 0000 0000 0000 0001
		{[]byte{0xC0, 0x10}, 16}, // 1100 0000 0001 0000 - after clearing pointer bits -> 0000 0000 0001 0000

		// not a pointer
		{[]byte{0x00, 0x00}, -1}, // 0000 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
		{[]byte{0x80, 0x00}, -1}, // 1000 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
		{[]byte{0x40, 0x00}, -1}, // 0100 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
	}

	for _, test := range tests {
		result, err := extractPointer(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, result, "For input %v, expected %d, but got %d", test.input, test.expected, result)
	}

	// error case
	tests = []struct {
		input    []byte
		expected int
	}{
		{[]byte{0xC0, 0x00, 0x00}, -1}, // 1100 0000 0000 0000 - after clearing pointer bits -> 0000 0000 0000 0000
	}

	for _, test := range tests {
		_, err := extractPointer(test.input)
		assert.Error(t, err)
	}
}
