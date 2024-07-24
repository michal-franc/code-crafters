package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

func (message *DNSMessage) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	encodedHeader, err := message.Header.Encode()
	if err != nil {
		return nil, err
	}
	buf.Write(encodedHeader)

	for _, question := range message.Questions {
		encodedQuestion, err := question.Encode()
		if err != nil {
			return nil, err
		}
		buf.Write(encodedQuestion)
	}

	for _, answer := range message.Answers {
		encodedAnswer, err := answer.Encode()
		if err != nil {
			return nil, err
		}
		buf.Write(encodedAnswer)
	}

	return buf.Bytes(), nil
}

func (message *DNSMessage) Decode(messageBytes []byte) error {

	message.Header = DNSHeader{}
	message.Questions = []DNSQuestion{}
	message.Answers = []DNSAnswer{}

	err := message.Header.Decode(messageBytes)
	if err != nil {
		return err
	}

	// 12 is start of question section
	offset := 12
	for range message.Header.QDCOUNT {
		question := DNSQuestion{}
		offset, err = question.Decode(messageBytes, offset)
		if err != nil {
			return fmt.Errorf("failure in decoding message on decoding question: %e", err)
		}
		message.Questions = append(message.Questions, question)
	}

	for range message.Header.ANCOUNT {
		answer := DNSAnswer{}
		offset, err = answer.Decode(messageBytes, offset)
		if err != nil {
			return fmt.Errorf("failure in decoding message on decoding answer: %e", err)
		}
		message.Answers = append(message.Answers, answer)
	}

	return nil
}

// in the rfc - https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
// if last two bits are 11 then its a pointer
func doesWordHasAPointer(word []byte) (bool, error) {

	if len(word) != 2 {
		return false, fmt.Errorf("provided word is not 2 bytes in size unable to proceed")
	}

	w := binary.BigEndian.Uint16(word)
	return hasBit(w, 15) && hasBit(w, 14), nil
}

func extractPointer(word []byte) (int, error) {

	if len(word) != 2 {
		return -1, fmt.Errorf("provided word is not 2 bytes in size unable to proceed to extract pointer")
	}

	w := binary.BigEndian.Uint16(word)

	// generates 1100 0000 0000 0000
	mask := 11 << 14

	// &^= does and not operation and will clear the bits that have 11
	// this will set zero if both w and mask are 1 and otherwise use the w
	// to remove pointer  indication and create a value from the rest of bits
	// which is the actuall offset value
	w &^= uint16(mask)

	return int(w), nil
}

// Will find a name in the byte array
// If compression found will decompress the name
// returns
// - byte representation of name
// - offset by which one should shift the bytes
func nameExtract(data []byte, startOffset int) ([]byte, int, error) {
	offset := startOffset
	lengthOfLabelSection := 0
	hasPointer := false
	buf := new(bytes.Buffer)

	// find the length of the name by counting offset in bytes by traversing  the encoded name
	// it reads the length adds it to offset until if finds 0 value which indicates the end of the encoded name

	for {
		word := data[offset : offset+2]
		isPointer, err := doesWordHasAPointer(word)
		if err != nil {
			return nil, 0, fmt.Errorf("name extraction failed: %e", err)
		}

		if isPointer {
			buf.Write(data[startOffset:offset])
			// by rfc the pointer is a 16 bit word (2 bytes)
			pointer, err := extractPointer(word)
			if err != nil {
				return nil, 0, fmt.Errorf("name extraction failed: %e", err)
			}

			lengthOfLabelSection = (offset + 2) - startOffset
			offset = pointer
			startOffset = pointer
			hasPointer = true
		}

		// get next byte
		oneByte := uint16(data[offset])

		// move offset by the length
		labelLength := int(oneByte)
		offset += labelLength
		// move the offset to the start of next byte
		offset++
		// if the next byte value is 0 then it is end
		if labelLength == 0 {
			if !hasPointer {
				lengthOfLabelSection = offset - startOffset
			}
			buf.Write(data[startOffset:offset])
			break
		}

		// this is just a precatuion so we dont create infinite loop
		if offset > len(data) {
			return nil, 0, fmt.Errorf("name extraction failed: offset moved past the messagesBytes bytes count indicating some bug in the loop")
		}
	}

	return buf.Bytes(), lengthOfLabelSection, nil
}

// split by .
// then for each splitted item create encoded value and add to buf
// encoded value example de => \x02de --- length 2 and then characters (or runes)
// then emit buff adding \x00 at the end - this is to indicate the end of label - important for decoding!
func nameEncoder(name string) []byte {
	if name == "" {
		// we need to return 0 as this is indicating the end of the name
		return []byte{0x00}
	}

	buf := new(bytes.Buffer)
	split := strings.Split(name, ".")
	for _, v := range split {
		length := len(v)

		buf.WriteByte(uint8(length)) // uint8 is important here as the number  has to occupy 1 byte
		buf.Write([]byte(v))
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

// split by .
// then for each splitted item create encoded value and add to buf
// example 8.8.8.8 -> 8888
// we effectively just remove `dot`
// but we cant just encode 8888 in byte it has be 8 8 8 8 each in 1 byte that is why simple algorithm to `remove .` won't work here
func ipV4Encoder(ip string) ([]byte, error) {
	buf := new(bytes.Buffer)

	split := strings.Split(ip, ".")

	if len(split) != 4 {
		return nil, fmt.Errorf("invalid IP address ip: %s", ip)
	}

	for _, v := range split {
		value, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failure when parsing sub value %v in ip: %s", v, ip)
		}

		if value > 255 || value < 0 {
			return nil, fmt.Errorf("the parsed value is not within the the ipv4 limit - value: %v in ip %s", value, ip)
		}

		// uint8 is important here as the value has to  fit into 1 byte
		if err := binary.Write(buf, binary.BigEndian, uint8(value)); err != nil {
			return nil, fmt.Errorf("failure when writing value to buffer")
		}
	}

	return buf.Bytes(), nil
}
