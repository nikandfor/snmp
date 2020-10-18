[![Documentation](https://pkg.go.dev/badge/github.com/nikandfor/snmp)](https://pkg.go.dev/github.com/nikandfor/snmp?tab=doc)
[![Build Status](https://travis-ci.com/nikandfor/snmp.svg?branch=master)](https://travis-ci.com/nikandfor/snmp)
[![CircleCI](https://circleci.com/gh/nikandfor/snmp.svg?style=svg)](https://circleci.com/gh/nikandfor/snmp)
[![codecov](https://codecov.io/gh/nikandfor/snmp/branch/master/graph/badge.svg)](https://codecov.io/gh/nikandfor/snmp)
[![GolangCI](https://golangci.com/badges/github.com/nikandfor/snmp.svg)](https://golangci.com/r/github.com/nikandfor/snmp)
[![Go Report Card](https://goreportcard.com/badge/github.com/nikandfor/snmp)](https://goreportcard.com/report/github.com/nikandfor/snmp)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nikandfor/snmp?sort=semver)

# snmp

Simple but powerful snmp client.

Minimal example
```go
conn, err := net.ListenPacket("udp", *addr)
if err != nil { /* ... */}

c := snmp.NewClient(conn)
defer c.Close() // <- conn is Closed here

go c.Run() // read incoming packets.

root, err := asn1.ParseOID(os.Args[1])
if err != nil { /* ... */}

p, err := c.Walk(a, root)
if err != nil {
	log.Fatalf("walk: %v", err)
}

for _, v := range p.Vars {
	fmt.Printf("%v\n", v)
}
```

See full example in [`./cmd/`](./cmd/) dir.
