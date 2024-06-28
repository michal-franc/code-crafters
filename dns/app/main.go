package main

import (
	"fmt"
	"github.com/alexflint/go-arg"
	"net"
)

func main() {

	var args struct {
		Resolver string
	}

	isResolver := false
	var udpConnResolver net.Conn
	var err error

	arg.MustParse(&args)

	if args.Resolver != "" {
		isResolver = true
		fmt.Println("Server configured to proxy to address: ", args.Resolver)

		udpConnResolver, err = net.Dial("udp", args.Resolver)
		if err != nil {
			fmt.Println("Failed to bind to address:", err)
			return
		}
		fmt.Println("Bind to resolver succesfull:  ", args.Resolver)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}

	defer func(udpConn *net.UDPConn) {
		err := udpConn.Close()
		if err != nil {
			fmt.Println("Failed to close udp connection", err)
			// this usually will happen when file is already closed so no need to retry
		}
	}(udpConn)

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		receivedMessage, err := decodeMessage(buf[:size])

		if err != nil {
			fmt.Println("couldnt decode message:", err)
		}

		ipEncoded, err := ipEncoder("8.8.8.8")
		if err != nil {
			fmt.Println("couldnt encode answer data:", err)
		}

		var questions []DNSQuestion
		var answers []DNSAnswer

		for _, questionReceived := range receivedMessage.Questions {
			questions = append(questions, DNSQuestion{
				Name:  questionReceived.Name,
				Class: 1,
				Type:  1,
			})
		}

		if !isResolver {
			for _, questionReceived := range receivedMessage.Questions {
				answers = append(answers, DNSAnswer{
					Name:   questionReceived.Name,
					Class:  1,
					Type:   1,
					TTL:    60,
					Length: 4,
					Data:   ipEncoded,
				})
			}
		} else {
			for _, questionReceived := range receivedMessage.Questions {
				newMessageToResolver := DNSMessage{
					Header:    receivedMessage.Header,
					Questions: []DNSQuestion{questionReceived},
				}

				newMessageToResolver.Header.QDCOUNT = 1

				forwardedMessage, err := newMessageToResolver.encode()
				if err != nil {
					fmt.Println("Failed to encode proxy message:", err)
				}

				fmt.Println("Sending message to resolver:  ", args.Resolver)
				_, err = udpConnResolver.Write(forwardedMessage)
				if err != nil {
					fmt.Println("Failed to send message to resolver:", err)
				}

				buf := make([]byte, 512)

				sizeRes, err := udpConnResolver.Read(buf)
				if err != nil {
					fmt.Println("Error receiving data:", err)
					break
				}

				fmt.Printf("Received %d bytes", sizeRes)

				responseResolver, err := decodeMessage(buf[:sizeRes])
				if err != nil {
					fmt.Println("failure on decoding response from resolver: ", err)
				}

				for _, answerReceived := range responseResolver.Answers {
					answers = append(answers, answerReceived)
				}
			}

			responseMessage := DNSMessage{
				Header: DNSHeader{
					ID:      receivedMessage.Header.ID,
					QDCOUNT: uint16(len(receivedMessage.Questions)),
					ANCOUNT: uint16(len(receivedMessage.Questions)),
					NSCOUNT: 0,
					ARCOUNT: 0,
				},
				Questions: questions,
				Answers:   answers,
			}

			responseMessage.Header.SetQR(true)
			err = responseMessage.Header.SetOpCode(receivedMessage.Header.GetOpCode())
			if err != nil {
				fmt.Println("Failed to set opcode:", err)
			}

			responseMessage.Header.SetRD(receivedMessage.Header.GetRD())

			if receivedMessage.Header.GetOpCode() == 0 {
				err = responseMessage.Header.SetRcode(0)
			} else {

				err = responseMessage.Header.SetRcode(4)
			}

			if err != nil {
				fmt.Println("Failed to set rcode:", err)
			}

			response, err := responseMessage.encode()

			if err != nil {
				fmt.Println("Failed to encode response:", err)
			}

			_, err = udpConn.WriteToUDP(response, source)
			if err != nil {
				fmt.Println("Failed to send response:", err)
			}

		}
	}
}
