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

func extractPointer(word []byte) (int, error) {

	if len(word) != 2 {
		return -1, fmt.Errorf("provided word is not 2 bytes in size unable to proceed to extract pointer")
	}

	w := binary.BigEndian.Uint16(word)

	// in the rfc - https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
	// if last two bits are 11 then its a pointer
	if hasBit(w, 15) && hasBit(w, 14) {
		// generates 1100 0000 0000 0000
		mask := 11 << 14

		// &^= does and not operation and will clear the bits that have 11
		// this will set zero if both w and mask are 1 and otherwise use the w
		// to remove pointer  indication and create a value from the rest of bits
		// which is the actuall offset value
		w &^= uint16(mask)

		return int(w), nil
	} else {
		// this was not a pointer
		return -1, nil
	}
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

	pointerCounter := 0
	maxPointerJumps := 100

	// find the length of the name by counting offset in bytes by traversing  the encoded name
	// it reads the length adds it to offset until if finds 0 value which indicates the end of the encoded name

	for {
		if pointerCounter > maxPointerJumps {
			return nil, -1, fmt.Errorf("reached maximum %d pointer counter, malicious dns query or a mistake somewhere", maxPointerJumps)
		}
		// we check if we  have found a label ending with pointer
		// This  has to be a first check as pointer has a special structure with two bits set to one
		// if this wouldnt be the first check pointer could be mistaken to be naext label size
		pointer, err := extractPointer(data[offset : offset+2])
		if err != nil {
			return nil, 0, fmt.Errorf("name extraction failed: %e", err)
		}

		// if we found pointer then we need write the label + shift the offset and move it to pointer

		// example of message with pointer
		// \0x03f00\x0c
		// \x0c is the pointer with the length 0
		if pointer != -1 {
			pointerCounter++
			// everything up to the pointer is start of the message so we need to write it
			buf.Write(data[startOffset:offset])

			// we need to add +2 as pointer occupies the last two bytes of the  label
			lengthOfLabelSection = (offset + 2) - startOffset

			// reset the offset to the pointer so that we can jump to a label that probably doesnt have pointer
			offset = pointer
			startOffset = pointer
			hasPointer = true
			continue
		}

		// loop through bytes and the lenghts of labels till you reach the end or pointer
		lengthOflabel := data[offset]

		// +1 here as the first byte is the lenght value so we ddont want to miss it
		// label is | length | char | char | char ... etc
		offset += int(lengthOflabel) + 1

		if lengthOflabel == 0x00 {
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
