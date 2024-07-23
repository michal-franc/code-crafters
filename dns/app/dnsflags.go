package main

import "fmt"

type Flags struct {
	Value uint16
}

func hasBit(n uint16, pos uint) bool {
	mask := uint16(1 << pos)
	val := n & mask
	return val > 0
}

func setBit(n uint16, pos uint) uint16 {
	mask := uint16(1 << pos)
	n = n | mask
	return n
}

func (f *Flags) GetQR() bool {
	return hasBit(f.Value, 15)
}

func (f *Flags) SetQR(value bool) {
	if value {
		f.Value = setBit(f.Value, 15)
	}
}

func (f *Flags) GetAA() bool {
	return hasBit(f.Value, 10)
}

func (f *Flags) SetAA(value bool) {
	if value {
		f.Value = setBit(f.Value, 10)
	}
}

func (f *Flags) GetTC() bool {
	return hasBit(f.Value, 9)
}

func (f *Flags) SetTC(value bool) {
	if value {
		f.Value = setBit(f.Value, 9)
	}
}

func (f *Flags) GetRD() bool {
	return hasBit(f.Value, 8)
}

func (f *Flags) SetRD(value bool) {
	if value {
		f.Value = setBit(f.Value, 8)
	}
}

func (f *Flags) GetRA() bool {
	return hasBit(f.Value, 7)
}

func (f *Flags) SetRA(value bool) {
	if value {
		f.Value = setBit(f.Value, 7)
	}
}

func (f *Flags) GetZ() uint16 {
	mask := uint16(16 + 32 + 64)
	return (f.Value & mask) >> 4
}

func (f *Flags) SetZ(value uint16) (err error) {
	if value >= 8 {
		return fmt.Errorf("invalid z value set - allowed 0 to 7: %d", value)
	}
	mask := value << 4 // shift to put correct value
	f.Value |= mask

	return nil
}

func (f *Flags) GetRcode() uint16 {
	mask := uint16(1 + 2 + 4 + 8)
	return f.Value & mask
}

func (f *Flags) SetRcode(value uint16) (err error) {
	if value >= 16 {
		return fmt.Errorf("invalid z value set - allowed 0 to 15: %d", value)
	}
	mask := value
	f.Value |= mask

	return nil
}

func (f *Flags) GetOpCode() uint16 {
	// OpCode is positioned from 1 to 4th bit in the first byte
	// apply mask 01111000 00000000 which takes 1 to 4 bits - BigEndian
	mask := uint16(2048 + 4096 + 8192 + 16834)
	// apply mask on the value to extract only the bits which are important
	// shift right as the OpCode starts at 11
	return (f.Value & mask) >> 11
}

func (f *Flags) SetOpCode(value uint16) (err error) {
	if value >= 16 {
		return fmt.Errorf("invalid opcode value set - allowed 0 to 15: %d", value)
	}
	mask := value << 11 // shift to put correct value
	f.Value |= mask

	return nil
}
