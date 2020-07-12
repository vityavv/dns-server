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
		// Below is the code to return an answer
		// go func(pc net.PacketConn, addr net.Addr, buf []byte) {
		// buf[2] |= 0x80        //what is a QR bit?
		// pc.WriteTo(buf, addr) //writes from buf to addr
		// }(pc, addr, buf[:n])
	}
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

type ResourceRecord struct {
	Name     []string
	Type     uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    string
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
		newRR.Type = binary.BigEndian.Uint16(packet[pos : pos+2])
		newRR.Class = binary.BigEndian.Uint16(packet[pos+2 : pos+4])
		newRR.Ttl = binary.BigEndian.Uint32(packet[pos+4 : pos+8])
		newRR.Rdlength = binary.BigEndian.Uint16(packet[pos+8 : pos+10])
		pos += 10
		newRR.Rdata = string(packet[pos : pos+int(newRR.Rdlength)])
		pos += int(newRR.Rdlength)
		records = append(records, newRR)
	}
	return
}
