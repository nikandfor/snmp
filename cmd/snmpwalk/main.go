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
	debug     = flag.String("debug", "", "debug http address to listen to")
	community = flag.String("community", "public", "SNMP Community")
	timeout   = flag.Duration("read-timeout", time.Second, "read timeout for each request")
	retries   = flag.Int("retries", 1, "SNMP request retries")
	nonreps   = flag.Int("non-repeaters", 0, "GetBulk argument")
	maxreps   = flag.Int("max-repetitions", 100, "GetBulk argument")
	version   = flag.String("version", "2c", "SNMP protocol version")
	telemetry = flag.Bool("telemetry", true, "Print request telemetry")
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
		log.Printf("version: %v", err)
		return
	}

	go c.Run()

	a := ParseAddr(*addr)
	//	log.Printf("addr: %v", a)

	var t *snmp.Telemetry
	if *telemetry {
		t = snmp.NewTelemetry()
	}

	for _, arg := range flag.Args() {
		root, err := asn1.ParseOID(arg)
		if err != nil {
			log.Fatalf("bad argument: %v", err)
		}

		p, err := c.Walk(a, root, t)
		for _, v := range p.Vars {
			fmt.Printf("%v\n", v)
		}

		if t != nil {
			log.Printf("vars: %v, version used: %v, repetitions: %d, %d", len(p.Vars), p.Version, p.NonRepeaters, p.MaxRepetitions)
		}

		if err != nil {
			log.Printf("walk: %v", err)
			break
		}
	}

	if t != nil {
		q0 := t.Requests.Query(0) * 1000
		q5 := t.Requests.Query(0.5) * 1000
		q9 := t.Requests.Query(0.9) * 1000
		q99 := t.Requests.Query(0.99) * 1000
		q1 := t.Requests.Query(1) * 1000
		rps := float64(t.Requests.Count()) / t.Duration.Seconds()
		log.Printf("%d (%d errors) requests made in %.1f secs: %.1f rps, quantiles ms: .0 %.1f, .5 %.1f, .9 %.1f, .99 %.1f, 1. %.1f",
			t.Requests.Count(), t.Errors, t.Duration.Seconds(), rps, q0, q5, q9, q99, q1)
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
