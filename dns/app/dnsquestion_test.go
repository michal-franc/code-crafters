package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDNSQuestionWithNameEncoding(t *testing.T) {

	testName := nameEncoder("1")

	question := DNSQuestion{
		Name: testName,
	}

	questionEncoded, err := question.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	// 1 is encoded as 0x01, and character 1 which is int("1"), and ending with 0x00
	expectedNameEncoding := []byte{0x01, byte(int('1')), 0x00}
	expectedNameEncoding = append(expectedNameEncoding, []byte{0, 0, 0, 0}...) // ... here will change the array to single elements
	assert.Equal(t, questionEncoded, expectedNameEncoding, "Question with Name '1' encoding")
}

func TestDNSQuestionWithStaticVariablesEncode(t *testing.T) {

	question := DNSQuestion{
		Type: uint16(1), // A
	}

	questionEncoded, err := question.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	assert.Equal(t, questionEncoded, []byte{0, 1, 0, 0}, "Question with A record encoding failed")

	question = DNSQuestion{
		Type: uint16(5), // CNAME
	}

	questionEncoded, err = question.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	assert.Equal(t, questionEncoded, []byte{0, 5, 0, 0}, "Question with CNAMe record encoding failed")

	question = DNSQuestion{
		Class: uint16(1), // default typical value as it indicated IN - Internet
	}

	questionEncoded, err = question.Encode()

	if err != nil {
		t.Error("Error while encoding DNS Message", err)
	}

	assert.Equal(t, questionEncoded, []byte{0, 0, 0, 1}, "Question with class IN failed")
}
