package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDNSAnswerEmptyEncode(t *testing.T) {

	answer := DNSAnswer{}

	answerEncoded, err := answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// answer with no data has 10 bytes
	assert.Equal(t, answerEncoded, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Empty Answer encoding problem")
}

func TestDNSAnswerWithStaticVariablesEncode(t *testing.T) {

	answer := DNSAnswer{
		Type: uint16(1), // A
	}

	answerEncoded, err := answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// Type is first 2 byte sequence in answer without Name
	assert.Equal(t, answerEncoded, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, "Answer with A record encoding failed")

	answer = DNSAnswer{
		Type: uint16(5), // CNAME
	}

	answerEncoded, err = answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// Type is first 2 byte sequence in answer without Name
	assert.Equal(t, answerEncoded, []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 0}, "Answer with CNAMe record encoding failed")

	answer = DNSAnswer{
		Class: uint16(1), // default typical value as it indicated IN - Internet
	}

	answerEncoded, err = answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	//Class Occupies 3rd and 4th byte
	assert.Equal(t, answerEncoded, []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "Answer with class IN failed")
}

func TestDNSAnswerWithNameEncoding(t *testing.T) {

	testName := nameEncoder("1")

	answer := DNSAnswer{
		Name: testName,
	}

	answerEncoded, err := answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// 1 is encoded as 0x01, and character 1 which is int("1"), and ending with 0x00
	expectedNameEncoding := []byte{0x01, byte(int('1')), 0x00}
	expectedNameEncoding = append(expectedNameEncoding, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...) // ... here will change the array to single elements
	assert.Equal(t, answerEncoded, expectedNameEncoding, "Answer with Name '1' encoding")
}

func TestDNSAnswerWithDataEncoding(t *testing.T) {

	testData, err := ipV4Encoder("8.8.8.8")
	assert.NoError(t, err)

	answer := DNSAnswer{
		Data: testData,
	}

	answerEncoded, err := answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// Data is kept at the end
	// we start with empty answer
	expectedNameEncoding := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// then we add the expected data encoded 4 bytes ot 8
	expectedNameEncoding = append(expectedNameEncoding, []byte{8, 8, 8, 8}...) // ... here will change the array to single elements
	assert.Equal(t, answerEncoded, expectedNameEncoding, "Answer with data encoded")
}

func TestDNSAnswerEncodeDecode(t *testing.T) {
	testData, err := ipV4Encoder("8.8.8.8")
	assert.NoError(t, err)

	answer := DNSAnswer{
		Name:   nameEncoder("mfranc.com"),
		Type:   1,
		Class:  5,
		TTL:    1000,
		Length: uint16(len(testData)),
		Data:   testData,
	}

	answerEncoded, err := answer.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	decodedAnswer := DNSAnswer{}
	_ = decodedAnswer.Decode(answerEncoded, 0)

	assert.Equal(t, answer, decodedAnswer)
}
