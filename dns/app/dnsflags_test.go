package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHasBit(t *testing.T) {

	assertHelper := func(value uint16, bitNumber uint, expected bool) {
		assert.Equal(t, expected, hasBit(value, bitNumber), "Expected %d to have bit %d %t - binary representation %b", value, bitNumber, expected, value)
	}

	assertHelper(8, 3, true)
	assertHelper(10, 1, true)
	assertHelper(64, 6, true)

	assertHelper(8, 1, false)
	assertHelper(9, 4, false)
}

func TestSetBit(t *testing.T) {

	assertHelper := func(value uint16, bitNumber uint, expected uint16) {
		actual := setBit(value, bitNumber)
		assert.Equal(t, expected, actual, "Expected %d to be equal %d after setting bit %d - binary representation expected: %b actual: %b", value, expected, bitNumber, expected, actual)
	}

	assertHelper(0, 3, 8)
	assertHelper(8, 3, 8)
	assertHelper(0, 1, 2)
	assertHelper(0, 0, 1)
}

func TestHeaderQR(t *testing.T) {
	testHeader := Flags{}

	assert.False(t, testHeader.GetQR())

	testHeader.SetQR(true)

	assert.True(t, testHeader.GetQR())
}

func TestHeaderRD(t *testing.T) {
	testHeader := Flags{}

	assert.False(t, testHeader.GetRD())

	testHeader.SetRD(true)

	assert.True(t, testHeader.GetRD())
}

func TestHeaderAA(t *testing.T) {
	testHeader := Flags{}

	assert.False(t, testHeader.GetAA())
	testHeader.SetAA(true)
	assert.True(t, testHeader.GetAA())
}

func TestHeaderTC(t *testing.T) {
	testHeader := Flags{}

	assert.False(t, testHeader.GetTC())
	testHeader.SetTC(true)
	assert.True(t, testHeader.GetTC())
}

func TestHeaderRA(t *testing.T) {
	testHeader := Flags{}

	assert.False(t, testHeader.GetRA())
	testHeader.SetRA(true)
	assert.True(t, testHeader.GetRA())
}

func TestHeaderZ(t *testing.T) {
	testHeader := Flags{}

	assert.Equal(t, uint16(0), testHeader.GetZ())
	err := testHeader.SetZ(1)
	assert.NoError(t, err)
	assert.Equal(t, uint16(1), testHeader.GetZ())

	err = testHeader.SetZ(8)
	assert.Error(t, err)
}

func TestHeaderRCcode(t *testing.T) {
	testHeader := Flags{}

	assert.Equal(t, uint16(0), testHeader.GetRcode())
	err := testHeader.SetRcode(1)
	assert.NoError(t, err)
	assert.Equal(t, uint16(1), testHeader.GetRcode())

	err = testHeader.SetRcode(16)
	assert.Error(t, err)
}

func TestHeaderOpCode(t *testing.T) {
	testHeader := Flags{}

	assert.Equal(t, uint16(0), testHeader.GetOpCode())
	err := testHeader.SetOpCode(1)
	assert.NoError(t, err)

	assert.Equal(t, uint16(1), testHeader.GetOpCode())
	err = testHeader.SetOpCode(15)
	assert.NoError(t, err)

	assert.Equal(t, uint16(15), testHeader.GetOpCode())

	err = testHeader.SetOpCode(16)
	assert.Error(t, err)
}
