package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/nikandfor/snmp"
)

var (
	listen = flag.String("listen", "", "addr to listen to")
	debug  = flag.String("debug", "", "debug http address to listen to")
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

	log.Printf("listening %v", conn.LocalAddr())

	log.Fatalf("dumper: %v", snmp.Dumper(conn))
}
