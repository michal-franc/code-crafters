package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
)

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

func (message *DNSMessage) encode() ([]byte, error) {
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
		offset = question.Decode(messageBytes, offset)
		message.Questions = append(message.Questions, question)
	}

	for range message.Header.ANCOUNT {
		answer := DNSAnswer{}
		offset = answer.Decode(messageBytes, offset)
		message.Answers = append(message.Answers, answer)
	}

	return nil
}

// in the rfc - https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
// if last two bits are 11 then its a pointer
func doesWordHasAPointer(word []byte) bool {
	w := binary.BigEndian.Uint16(word)
	return hasBit(w, 15) && hasBit(w, 14)
}

func extractPointer(b []byte) int {
	w := binary.BigEndian.Uint16(b)

	// generates 1100 0000 0000 0000
	mask := 11 << 14

	// &^= does and not operation and will clear the bits that have 11
	// this will set zero if both w and mask are 1 and otherwise use the w
	// to remove pointer  indication and create a value from the rest of bits
	// which is the actuall offset value
	w &^= uint16(mask)

	return int(w)
}

// Will find a name in the byte array
// If compression found will decompress the name
// returns
// - byte representation of name
// - offset by which one should shift the bytes

// TODO: there has to be a better algorithm here
func nameExtract(data []byte, startOffset int) ([]byte, int) {
	// names are encoded by
	// | length byte | x* bytes containg the characters each character byte |

	offset := startOffset
	lengthOfLabelSection := 0
	hasPointer := false
	buf := new(bytes.Buffer)
	// find the length of the name by counting offset in bytes by traversing  the encoded name
	// it reads the length adds it to offset until if finds 0 value which indicates the end of the encoded name
	for {
		word := data[offset : offset+2]
		isPointer := doesWordHasAPointer(word)
		if isPointer {
			buf.Write(data[startOffset:offset])
			// by rfc the pointer is a 16 bit word (2 bytes)
			pointer := extractPointer(word)
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
			//TODO: more gracefull shutdown maybe return err
			log.Fatal("CRASH: while decoding DNS message moved past the messageBytes bytes count")
		}
	}

	return buf.Bytes(), lengthOfLabelSection
}

// split by .
// then for each splitted item create encoded value and add to buf
// encoded value example de => \x02de --- length 2 and then characters (or runes)
// then emit buff adding \x00 at the end - this is to indicate the end of label - important for decoding!
// TODO: add more tests also on boundaries
// TODO: add logic to validate if the limits are met and kept in the boundaries
func nameEncoder(name string) []byte {
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

// TODO: add more tests also on boundaries
// TODO: add logic to validate the ip before encoding
func ipEncoder(ip string) ([]byte, error) {
	buf := new(bytes.Buffer)

	split := strings.Split(ip, ".")

	for _, v := range split {
		value, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			fmt.Println("ipEncoder failure when creating value")
			return nil, nil
		}

		// uint8 is important here as the value has to  fit into 1 byte
		if err := binary.Write(buf, binary.BigEndian, uint8(value)); err != nil {
			fmt.Println("ipEncoder failure when writing value to buffer")
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
