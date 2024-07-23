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

type DNSHeader struct {
	ID      uint16
	FLAGS   Flags
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}
type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

type DNSAnswer struct {
	Name   []byte
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

func (msg *DNSMessage) encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, msg.Header); err != nil {
		return nil, err
	}

	for _, question := range msg.Questions {
		buf.Write(question.Name)
		if err := binary.Write(buf, binary.BigEndian, question.Type); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, question.Class); err != nil {
			return nil, err
		}
	}

	for _, answer := range msg.Answers {
		buf.Write(answer.Name)
		if err := binary.Write(buf, binary.BigEndian, answer.Type); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, answer.Class); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, answer.TTL); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, answer.Length); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, answer.Data); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func decodeMessage(messageBytes []byte) (DNSMessage, error) {

	message := DNSMessage{
		Header:    DNSHeader{},
		Questions: []DNSQuestion{},
		Answers:   []DNSAnswer{},
	}

	headerBuffer := bytes.NewBuffer(messageBytes[0:12])

	err := binary.Read(headerBuffer, binary.BigEndian, &message.Header)
	if err != nil {
		return DNSMessage{}, err
	}

	startOfQuestionSection := 12
	offset := startOfQuestionSection

	for range message.Header.QDCOUNT {
		name, offsetName := nameExtract(messageBytes, startOfQuestionSection)
		offset += offsetName
		question := DNSQuestion{
			Name: name,
		}

		question.Type = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
		offset += 2

		question.Class = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
		offset += 2

		message.Questions = append(message.Questions, question)

		// move to next question
		startOfQuestionSection = offset
	}

	startOfAnswerSection := offset
	offset = startOfAnswerSection

	for range message.Header.ANCOUNT {
		name, offsetName := nameExtract(messageBytes, startOfAnswerSection)
		offset += offsetName
		answer := DNSAnswer{
			Name: name,
		}

		answer.Type = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
		offset += 2

		answer.Class = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
		offset += 2

		answer.TTL = binary.BigEndian.Uint32(messageBytes[offset : offset+4])
		offset += 4

		answer.Length = binary.BigEndian.Uint16(messageBytes[offset : offset+2])
		offset += 2

		answer.Data = messageBytes[offset : offset+4]
		offset += 4

		message.Answers = append(message.Answers, answer)
		startOfAnswerSection = offset
	}

	return message, nil
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

func nameEncoder(name string) []byte {
	// split by .
	// then for each splitted item create encoded value and add to buf
	// then emit buff adding \x00 at the end
	buf := new(bytes.Buffer)
	split := strings.Split(name, ".")
	for _, v := range split {
		length := len(v)

		buf.WriteByte(uint8(length))
		buf.Write([]byte(v))
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func ipEncoder(ip string) ([]byte, error) {
	buf := new(bytes.Buffer)

	split := strings.Split(ip, ".")

	for _, v := range split {
		value, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			fmt.Println("ipEncoder failure when creating value")
			return nil, nil
		}

		if err := binary.Write(buf, binary.BigEndian, uint8(value)); err != nil {
			fmt.Println("ipEncoder failure when writing value to buffer")
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
