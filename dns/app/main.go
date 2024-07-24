package main

import (
	"fmt"
	"github.com/alexflint/go-arg"
	"log"
	"net"
)

var args struct {
	Resolver string
}

func main() {
	var udpConnResolver net.Conn
	var err error

	arg.MustParse(&args)

	if args.Resolver != "" {
		fmt.Println("Server configured to proxy to address: ", args.Resolver)

		udpConnResolver, err = net.Dial("udp", args.Resolver)

		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {
				fmt.Println("Failed to close connection", err)
				// this usually will happen when file is already closed so no need to retry
			}
		}(udpConnResolver)

		if err != nil {
			log.Fatal("failed to dial resolver: ", err)
		}

		fmt.Println("Dial to resolver sucesfull:  ", args.Resolver)
	}

	fmt.Println("Server configured to listen: ", "127.0.0.1:2053")
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		log.Fatal("failed to resolve UDP address: ", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal("failed to bind to address: ", err)
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

		receivedMessage := DNSMessage{}
		err = receivedMessage.Decode(buf[:size])
		if err != nil {
			fmt.Printf("Couldn't decode message: %e", err)
			continue
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

		if udpConnResolver != nil {
			answers, err = contactResolver(receivedMessage, udpConnResolver)
			if err != nil {
				fmt.Printf("Error when contacting resolver: %e\n", err)
			}
		} else {
			answers, err = generateLocalResponse(receivedMessage)
			if err != nil {
				fmt.Printf("Error when reaching local dns cache: %e\n", err)
			}
		}
		response, err := generateReponse(receivedMessage, questions, answers)
		if err != nil {
			fmt.Printf("Error when generating response: %e\n", err)
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Printf("Failed to send response: %e\n", err)
		}
	}
}

func contactResolver(receivedMessage DNSMessage, udpConnResolver net.Conn) ([]DNSAnswer, error) {
	var answers []DNSAnswer
	for _, questionReceived := range receivedMessage.Questions {
		newMessageToResolver := DNSMessage{
			Header:    receivedMessage.Header,
			Questions: []DNSQuestion{questionReceived},
		}

		// We can only send one question at a time to resolver
		// Actually apparently this feature to sent multiple questions in one DNS query is not really used
		newMessageToResolver.Header.QDCOUNT = 1

		forwardedMessage, err := newMessageToResolver.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode query to resolver: %e", err)
		}

		fmt.Println("Sending message to resolver:  ", args.Resolver)
		_, err = udpConnResolver.Write(forwardedMessage)
		if err != nil {
			return nil, fmt.Errorf("failed to send message to resolver: %e", err)
		}

		buf := make([]byte, 512)

		sizeRes, err := udpConnResolver.Read(buf)
		if err != nil {
			fmt.Println("error receiving data:", err)
			//TODO: retry logic
			//TODO: if retry failed return err
			break
		}

		fmt.Printf("Received %d bytes", sizeRes)

		responseFromeResolver := DNSMessage{}
		err = responseFromeResolver.Decode(buf[:sizeRes])
		if err != nil {
			return nil, fmt.Errorf("failure on decoding response from resolver: %e", err)
		}

		for _, answerReceived := range responseFromeResolver.Answers {
			answers = append(answers, answerReceived)
		}
	}
	return answers, nil
}

func generateReponse(receivedMessage DNSMessage, questions []DNSQuestion, answers []DNSAnswer) ([]byte, error) {
	responseMessage := DNSMessage{
		Header: DNSHeader{
			ID:      receivedMessage.Header.ID,
			QDCOUNT: uint16(len(receivedMessage.Questions)),
			ANCOUNT: uint16(len(receivedMessage.Questions)),
			NSCOUNT: 0, // TODO: Not supported
			ARCOUNT: 0, // TODO Not Supported
		},
		Questions: questions,
		Answers:   answers,
	}

	//TODO: hide the complexity of what QR means and just create a flag IS this response or query
	responseMessage.Header.FLAGS.SetQR(true)

	err := responseMessage.Header.FLAGS.SetOpCode(receivedMessage.Header.FLAGS.GetOpCode())
	if err != nil {
		return nil, fmt.Errorf("failed to set opcode: %e", err)
	}

	responseMessage.Header.FLAGS.SetRD(receivedMessage.Header.FLAGS.GetRD())

	if receivedMessage.Header.FLAGS.GetOpCode() == 0 {
		err = responseMessage.Header.FLAGS.SetRcode(0)
	} else {
		//TODO: why in the task we should set rcode to 4?
		err = responseMessage.Header.FLAGS.SetRcode(4)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to set rcode: %e", err)
	}

	response, err := responseMessage.Encode()

	if err != nil {
		return nil, fmt.Errorf("failed to encode response: %e", err)
	}
	return response, nil
}

func generateLocalResponse(receivedMessage DNSMessage) ([]DNSAnswer, error) {
	// This returns static message
	var answers []DNSAnswer

	ipEncoded, err := ipV4Encoder("8.8.8.8")
	if err != nil {
		fmt.Println("Couldnt encode answer data:", err)
	}

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

	return answers, nil
}
