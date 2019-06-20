package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/nikandfor/snmp"
	"github.com/nikandfor/snmp/asn1"
)

var (
	listen    = flag.String("listen", "", "addr to listen to")
	addr      = flag.String("addr", "", "addr to send request to")
	debug     = flag.String("http", "", "debug address to listen to")
	community = flag.String("community", "public", "SNMP Community")
	timeout   = flag.Duration("read-timeout", time.Second, "read timeout for each request")
	retries   = flag.Int("retries", 1, "SNMP request retries")
	nonreps   = flag.Int("non-repeaters", 0, "GetBulk argument")
	maxreps   = flag.Int("max-repetitions", 100, "GetBulk argument")
	version   = flag.String("version", "2c", "SNMP protocol version")
)

func main() {
	flag.Parse()

	if *debug != "" {
		go func() {
			panic(http.ListenAndServe(*debug, http.DefaultServeMux))
		}()
	}

	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	// conn will be closed at snmp.Client.Close()

	c := snmp.NewClient(conn)
	defer c.Close() // <- conn is Closed here

	c.ReadTimeout = *timeout
	c.Community = *community
	c.Retries = *retries
	c.NonRepeaters = *nonreps
	c.MaxRepetitions = *maxreps
	c.Version, err = snmp.ParseVersion(*version)
	if err != nil {
		log.Fatal(err)
	}

	go c.Run()

	a := ParseAddr(*addr)
	//	log.Printf("addr: %v", a)

	for _, arg := range flag.Args() {
		root := asn1.ParseOID(arg)

		p, err := c.Walk(a, root)
		if err != nil {
			log.Fatalf("walk: %v", err)
		}

		for _, v := range p.Vars {
			fmt.Printf("  %v\n", v)
		}
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
