package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8000")
	fmt.Printf("%v\n", addr)
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	defer udpConn.Close()

	for {
		buf := make([]byte, 1024) //is 1024 the maximum packet size?
		// n = number of bytes (int)
		n, udpAddr, err := udpConn.ReadFromUDP(buf) // copies into buf
		fmt.Printf("udp: %v\n", udpAddr)
		if err != nil {
			continue
		}
		buf = buf[:n]
		header, questions, answers, authorities, additionalRecords, err := parsePacket(buf)
		fmt.Printf("Header: %#v\nQuestions: %#v\nAnswers: %#v\nAuthorities: %#v\nAdditional Records: %#v\n", header, questions, answers, authorities, additionalRecords)

		//let's just hard-code this one in: 199.7.91.13 (d.root-servers.net)
		// ROOT_SERVER := "199.7.91.13"
		//ROOT_SERVER := binary.BigEndian.Uint32([]byte{199, 7, 91, 13})
		ROOT_SERVER := []byte{199, 7, 91, 13} //has to be like this for Rdata field.

		if header.Opcode != QUERY {
			panic("Found a non-query opcode and I don't know what to do (TODO)")
		}

		//start crafting response
		rHeader := Header{
			Id:      header.Id,
			Qr:      true,
			Opcode:  QUERY,
			Aa:      false,
			Tc:      false,
			Rd:      header.Rd,
			Ra:      true,  //technically no, TODO
			Ad:      false, //TODO, figure out what this means https://tools.ietf.org/html/rfc4035#section-3.2.3 (probably ok to keep it 0 because older RFCs didn't have it)
			Cd:      header.Cd,
			Qdcount: header.Qdcount, //copying question section from query to response
		}
		rQuestions := questions
		//Fields left out: Rcode, Ancount, Nscount, Arcount
		if !header.Rd { //they don't want recursion
			rHeader.Rcode = NO_ERR
			rHeader.Ancount = 0
			rHeader.Nscount = 1 //This is where our root server goes. TODO: when you get to the cache, make this more complex than just sending the root server i.e. remember other authorities
			rHeader.Arcount = 1
			rAnswers := []ResourceRecord{}
			convertedDomain := convertToDomainName([]string{"d", "root-servers", "net"})
			rAuthorities := []ResourceRecord{ResourceRecord{
				Name:     []string{},
				Type:     NS,
				Class:    1, //INternet
				Ttl:      3600000,
				Rdlength: uint16(len(convertedDomain)),
				Rdata:    convertedDomain,
			}}
			rAdditionalRecords := []ResourceRecord{ResourceRecord{
				Name:     []string{"d", "root-servers", "net"},
				Type:     A,
				Class:    1,
				Ttl:      3600000,
				Rdlength: 4,
				Rdata:    ROOT_SERVER,
			}}
			fmt.Printf("===RESPONSE===\nHeader: %#v\nQuestions: %#v\nAnswers: %#v\nAuthorities: %#v\nAdditional Records: %#v\n", rHeader, rQuestions, rAnswers, rAuthorities, rAdditionalRecords)
			responsePacket := packetify(rHeader, rQuestions, rAnswers, rAuthorities, rAdditionalRecords)
			udpConn.WriteTo(responsePacket, udpAddr)
		} else {
			panic("Not implemented feature reached")
		}

		// Below is the code to return an answer
		// go func(pc net.PacketConn, addr net.Addr, buf []byte) {
		// buf[2] |= 0x80        //what is a QR bit?
		// pc.WriteTo(buf, addr) //writes from buf to addr
		// }(pc, addr, buf[:n])
	}
}

func convertToDomainName(name []string) (result []byte) {
	for _, s := range name {
		result = append(result, byte(len(s)))
		result = append(result, []byte(s)...)
	}
	result = append(result, 0)
	return
}

type Opcode int

const (
	QUERY Opcode = iota
	IQUERY
	STATUS
)

type Rcode int

const (
	NO_ERR Rcode = iota
	FORMAT_ERR
	SERVER_FAIL
	NAME_ERR
	NOT_IMPLEMENTED
	REFUSED
)

type Header struct {
	Id     uint16 //[2]byte
	Qr     bool   // 0 = query, 1 = response
	Opcode Opcode
	Aa     bool
	Tc     bool
	Rd     bool
	Ra     bool
	// reserved bit here
	Ad      bool
	Cd      bool
	Rcode   Rcode
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

type Question struct {
	Qname  []string
	Qtype  uint16
	Qclass uint16
}

type TYPE uint16

const (
	A     = iota + 1 //host address
	NS               // authoritative name server
	MD               //obsolete mail destination
	MF               //obsolete mail forwarder
	CNAME            //canonical name for alias
	SOA              //start of a zone of authority
	MB               //mailbox domain name
	MG               //mail group member
	MR               //mail rename domain name
	NULL
	WKS   //well known service desc.
	PTR   //domain name pointer
	HINFO // host information
	MINFO //mailbox/mail list information
	MX    //mail exchange
	TXT   //text strings
	//TODO find more
)

type ResourceRecord struct {
	Name     []string
	Type     TYPE
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    []byte
}

func parsePacket(packet []byte) (header Header, questions []Question, answers []ResourceRecord, authorities []ResourceRecord, additionalRecords []ResourceRecord, err error) {
	headerBytes := packet[:12]
	pos := 12

	header = Header{
		Id:      binary.BigEndian.Uint16(headerBytes[:2]),
		Qr:      bool(((headerBytes[2] >> 7) & 1) == 1),
		Opcode:  Opcode((headerBytes[2] >> 3) & 0b1111),
		Aa:      bool(((headerBytes[2] >> 2) & 1) == 1),
		Tc:      bool(((headerBytes[2] >> 1) & 1) == 1),
		Rd:      bool((headerBytes[2] & 1) == 1),
		Ra:      bool(((headerBytes[3] >> 7) & 1) == 1),
		Ad:      bool(((headerBytes[3] >> 5) & 1) == 1),
		Cd:      bool(((headerBytes[3] >> 4) & 1) == 1),
		Rcode:   Rcode(headerBytes[2] & 0b1111),
		Qdcount: binary.BigEndian.Uint16(headerBytes[4:6]),
		Ancount: binary.BigEndian.Uint16(headerBytes[6:8]),
		Nscount: binary.BigEndian.Uint16(headerBytes[8:10]),
		Arcount: binary.BigEndian.Uint16(headerBytes[10:]),
	}

	questions = make([]Question, 0, int(header.Qdcount))
	for q := 0; q < cap(questions); q++ {
		name, pos := getName(packet, pos)
		questions = append(questions, Question{
			Qname:  name,
			Qtype:  binary.BigEndian.Uint16(packet[pos : pos+2]),
			Qclass: binary.BigEndian.Uint16(packet[pos+2 : pos+4]),
		})
		pos += 4
	}

	answers, pos = parseRR(packet, pos, int(header.Ancount))
	authorities, pos = parseRR(packet, pos, int(header.Nscount))
	additionalRecords, pos = parseRR(packet, pos, int(header.Arcount))

	//TODO: There seems to be some part of the packet left (i.e. there is still data after the pos in the packet)
	//I don't know what's up with that but it seems to cause no harm so I'm gonna ignore it?
	return
}

func getName(packet []byte, ipos int) ([]string, int) {
	pos := ipos
	var name []string
	for {
		length := uint8(packet[ipos])
		if length == 0 {
			ipos++
			break
		}
		if length&0b11000000 == 0b11000000 {
			pos = int(binary.BigEndian.Uint16([]byte{packet[ipos] & 0b00111111, packet[ipos+1]}))
			ipos++                      //2 total are consumed, one here and one afterwards
			length = uint8(packet[pos]) // don't think there'll be pointers to pointers
		} else {
			pos = ipos + 1
		}
		ipos++
		part := string(packet[pos : pos+int(length)])
		if pos == ipos {
			ipos += int(length)
		}
		name = append(name, part)
	}
	return name, ipos
}

func parseRR(packet []byte, ipos int, count int) (records []ResourceRecord, pos int) {
	pos = ipos
	for q := 0; q < count; q++ {
		newRR := ResourceRecord{Name: []string{}}
		newRR.Name, pos = getName(packet, pos)
		newRR.Type = TYPE(binary.BigEndian.Uint16(packet[pos : pos+2]))
		newRR.Class = binary.BigEndian.Uint16(packet[pos+2 : pos+4])
		newRR.Ttl = binary.BigEndian.Uint32(packet[pos+4 : pos+8])
		newRR.Rdlength = binary.BigEndian.Uint16(packet[pos+8 : pos+10])
		pos += 10
		newRR.Rdata = packet[pos : pos+int(newRR.Rdlength)]
		pos += int(newRR.Rdlength)
		records = append(records, newRR)
	}
	return
}

// hate that I have to do this SMH
func bint(b bool) int {
	if b {
		return 1
	}
	return 0
}

func packetify(header Header, questions []Question, answers []ResourceRecord, authorities []ResourceRecord, additionalRecords []ResourceRecord) (packet []byte) {
	//to unpack numbers into []bytes, the binary package requires that the []byte be passed to the function instead of returning a []byte
	//I don't know why, but here are some containers for numbers that I can put the numbers into before appending that to the packet.
	uint16cont := make([]byte, 2)

	//HEADER
	binary.BigEndian.PutUint16(uint16cont, header.Id)
	packet = append(packet, uint16cont...)
	packet = append(packet, byte((bint(header.Qr)<<7)+(int(header.Opcode)<<3)+(bint(header.Aa)<<2)+(bint(header.Tc)<<1)+bint(header.Rd)))
	//reserved bit between Ra and Ad
	packet = append(packet, byte((bint(header.Ra)<<7)+(bint(header.Ad)<<5)+(bint(header.Cd)<<4)+int(header.Rcode)))
	binary.BigEndian.PutUint16(uint16cont, header.Qdcount)
	packet = append(packet, uint16cont...)
	binary.BigEndian.PutUint16(uint16cont, header.Ancount)
	packet = append(packet, uint16cont...)
	binary.BigEndian.PutUint16(uint16cont, header.Nscount)
	packet = append(packet, uint16cont...)
	binary.BigEndian.PutUint16(uint16cont, header.Arcount)
	packet = append(packet, uint16cont...)

	//QUESTION
	for _, question := range questions {
		packet = append(packet, convertToDomainName(question.Qname)...)
		binary.BigEndian.PutUint16(uint16cont, question.Qtype)
		packet = append(packet, uint16cont...)
		binary.BigEndian.PutUint16(uint16cont, question.Qclass)
		packet = append(packet, uint16cont...)
	}

	packet = append(packet, packetifyRR(answers)...)
	packet = append(packet, packetifyRR(authorities)...)
	packet = append(packet, packetifyRR(additionalRecords)...)
	return
}

func packetifyRR(rrs []ResourceRecord) (packet []byte) {
	uint16cont := make([]byte, 2)
	uint32cont := make([]byte, 4)
	for _, rr := range rrs {
		packet = append(packet, convertToDomainName(rr.Name)...)
		binary.BigEndian.PutUint16(uint16cont, uint16(rr.Type))
		packet = append(packet, uint16cont...)
		binary.BigEndian.PutUint16(uint16cont, rr.Class)
		packet = append(packet, uint16cont...)
		binary.BigEndian.PutUint32(uint32cont, rr.Ttl)
		packet = append(packet, uint32cont...)
		binary.BigEndian.PutUint16(uint16cont, rr.Rdlength)
		packet = append(packet, uint16cont...)
		packet = append(packet, rr.Rdata...)
	}
	return
}
