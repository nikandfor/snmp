package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/nikandfor/snmp"
	"github.com/nikandfor/snmp/asn1"
)

var (
	listen    = flag.String("listen", "", "addr to listen to")
	addr      = flag.String("addr", "", "addr to send request to")
	community = flag.String("community", "public", "SNMP Community")
	timeout   = flag.Duration("read-timeout", time.Second, "read timeout for each request")
	version   = flag.String("version", "2c", "SNMP protocol version")
	snmpcmd   = flag.String("cmd", "getnext", "SNMP protocol command to send")
)

func main() {
	flag.Parse()

	addr := ParseAddr(*addr)

	cmds := map[string]snmp.Command{
		"get":     snmp.Get,
		"getnext": snmp.GetNext,
		"getbulk": snmp.GetBulk,
	}

	cmd, ok := cmds[*snmpcmd]
	if !ok {
		log.Fatalf("Unsupported command: %v", *snmpcmd)
	}

	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}

	c := snmp.NewClient(conn)
	defer c.Close() // <- conn is Closed here

	c.ReadTimeout = *timeout
	c.Community = *community
	c.Version, err = snmp.ParseVersion(*version)
	if err != nil {
		log.Printf("version: %v", err)
		return
	}

	obj := flag.Arg(0)
	if obj == "" {
		obj = "1.3"
	}

	oid, err := asn1.ParseOID(obj)
	if err != nil {
		log.Printf("object id expected: %v", err)
		return
	}

	err = c.Send(addr, &snmp.PDU{
		Version:        c.Version,
		Community:      c.Community,
		Command:        cmd,
		ReqID:          rand.Int31n(10000),
		MaxRepetitions: 10,
		Vars:           []snmp.Var{{ObjectID: oid, Type: snmp.Null}},
	})
	if err != nil {
		log.Printf("Send: %v", err)
		return
	}

	for {
		addr, p, err := c.Read(nil, nil)
		if err != nil {
			log.Printf("Read: %v", err)
			return
		}

		fmt.Printf("from %-15v %v", addr, p.Dump())
	}
}

func ParseAddr(a string) net.Addr {
	addr, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		addr, err = net.ResolveUDPAddr("udp", a+":161")
	}
	if err != nil {
		log.Fatalf("Parse addr: %v", err)
	}

	return addr
}
