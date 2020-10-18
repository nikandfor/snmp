package snmp

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/beorn7/perks/quantile"

	"github.com/nikandfor/snmp/asn1"
)

var ( // errors
	ErrReadTimeout = errors.New("timeout")
	ErrExtraData   = errors.New("extra data")
	ErrClosed      = errors.New("closed client")
)

type (
	Type    = asn1.Type
	Command = Type
	Version int

	Var struct {
		ObjectID asn1.OID
		Type     asn1.Type
		Value    interface{}
	}

	PDU struct {
		Version   Version
		Community string

		Command Command
		ReqID   int32

		NonRepeaters, MaxRepetitions int

		ErrorStatus, ErrorIndex int

		Vars []Var
	}

	Client struct {
		conn net.PacketConn

		Receive chan<- Packet

		ReadTimeout time.Duration
		Retries     int

		Version   Version
		Community string

		NonRepeaters   int
		MaxRepetitions int

		mu    sync.Mutex
		reqid int32
		reqs  map[int32]chan Packet

		stopc chan struct{}
	}

	Packet struct {
		Addr net.Addr
		PDU  *PDU
		Err  error
	}

	Telemetry struct {
		Requests *quantile.Stream
		Duration time.Duration
		Errors   int
	}
)

const ( // Versions
	Version1  Version = 0
	Version2c Version = 1
	Version3  Version = 3
)

const ( // Commands
	Get      Command = asn1.Context | asn1.Constructor | 0x00
	GetNext  Command = asn1.Context | asn1.Constructor | 0x01
	Response Command = asn1.Context | asn1.Constructor | 0x02
	Set      Command = asn1.Context | asn1.Constructor | 0x03
	Trap     Command = asn1.Context | asn1.Constructor | 0x04
	GetBulk  Command = asn1.Context | asn1.Constructor | 0x05
)

const ( // Types
	Boolean     Type = asn1.Universal | 0x1
	Integer     Type = asn1.Universal | 0x2
	BitString   Type = asn1.Universal | 0x3
	OctetString Type = asn1.Universal | 0x4
	Null        Type = asn1.Universal | 0x5
	ObjectID    Type = asn1.Universal | 0x6
	Sequence    Type = asn1.Universal | 0x10
	TypeSet     Type = asn1.Universal | 0x11

	IPAddress  Type = asn1.Application | 0x0
	Counter    Type = asn1.Application | 0x1
	Gauge      Type = asn1.Application | 0x2
	Timeticks  Type = asn1.Application | 0x3
	Opaque     Type = asn1.Application | 0x4
	Counter64  Type = asn1.Application | 0x6
	Float      Type = asn1.Application | 0x8
	Double     Type = asn1.Application | 0x9
	Integer64  Type = asn1.Application | 0x10
	Unsigned64 Type = asn1.Application | 0x11

	NoSuchObject   Type = asn1.Context | asn1.Primitive | 0x0
	NoSuchInstance Type = asn1.Context | asn1.Primitive | 0x1
	EndOfMIBView   Type = asn1.Context | asn1.Primitive | 0x2
)

const ( // Error statuses
	NoError = iota
	TooBigError
	NoSuchNameError
	BadValueError
	ReadOnlyError
	GeneralError
)

// NewTelemetry returns inited telemetry object
func NewTelemetry() *Telemetry {
	return &Telemetry{
		Requests: quantile.NewHighBiased((time.Millisecond / 10).Seconds()),
	}
}

// NewClient creates SNMP client with default options
func NewClient(conn net.PacketConn) *Client {
	return &Client{
		conn:           conn,
		ReadTimeout:    time.Second,
		Retries:        1,
		Version:        Version2c,
		Community:      "public",
		NonRepeaters:   0,
		MaxRepetitions: 50,
		reqid:          rand.Int31n(0x1000000),
		reqs:           make(map[int32]chan Packet),
		stopc:          make(chan struct{}),
	}
}

// Send sends Protocol Data Unit to addr
func (c *Client) Send(addr net.Addr, p *PDU) error {
	b := p.EncodeTo(nil)

	_, err := c.conn.WriteTo(b, addr)

	return err
}

// Read reads Protocol Data Unit from connection
func (c *Client) Read(buf []byte, p *PDU) (net.Addr, *PDU, error) {
	if buf == nil {
		buf = make([]byte, 0x4000)
	}

	err := c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		return nil, nil, err
	}
	n, addr, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}

	if p == nil {
		p = new(PDU)
	}
	err = p.Decode(buf[:n])

	return addr, p, err
}

// Call sends Protocol Data Unit to address and waits for response for c.ReadTimeout
func (c *Client) Call(addr net.Addr, p *PDU) (_ *PDU, err error) {
	//	defer func() {
	//		log.Printf("Call %v %+v -> %v", addr, p, err)
	//	}()

	rc := make(chan Packet, 1)

	c.mu.Lock()
again:
	c.reqid++
	reqid := c.reqid
	if _, ok := c.reqs[reqid]; ok {
		goto again
	}
	c.reqs[reqid] = rc
	c.mu.Unlock()

	p.ReqID = reqid

	defer func() {
		c.mu.Lock()
		delete(c.reqs, reqid)
		c.mu.Unlock()
	}()

	err = c.Send(addr, p)
	if err != nil {
		return nil, err
	}

	select {
	case resp := <-rc:
		return resp.PDU, resp.Err
	case <-time.After(c.ReadTimeout):
		return nil, ErrReadTimeout
	}
}

// Walk scans addr for variables with prefix root.
// It retries on fail and downgrade protocol version if no answer.
// Additional arguments are supported:
//     *PDU - use that pdu instead of default
//     Version - set protocol version
//     Command - set command
//     *Telemetry - collect telemetry of requests
func (c *Client) Walk(addr net.Addr, root asn1.OID, args ...interface{}) (*PDU, error) {
	p := &PDU{
		Version:        c.Version,
		Community:      c.Community,
		Command:        GetBulk,
		NonRepeaters:   c.NonRepeaters,
		MaxRepetitions: c.MaxRepetitions,
	}

	var t *Telemetry
	var start time.Time
	for _, a := range args {
		switch a := a.(type) {
		case nil:
		case *PDU:
			p = a
		case Version:
			p.Version = a
		case Command:
			p.Command = a
		case *Telemetry:
			t = a
			start = time.Now()
		}
	}

	var vars []Var

	var err error
	var resp *PDU
	obj := root
	try := 0
out:
	for {
		if cap(p.Vars) == 0 {
			p.Vars = []Var{{ObjectID: obj, Type: asn1.Null}}
		} else {
			p.Vars = p.Vars[:1]
			p.Vars[0] = Var{ObjectID: obj, Type: asn1.Null}
		}

		var st time.Time
		if t != nil {
			st = time.Now()
		}

		resp, err = c.Call(addr, p)

		if t != nil {
			t.Requests.Insert(time.Since(st).Seconds())
			if err != nil || resp.ErrorStatus != 0 {
				t.Errors++
			}
		}

		switch {
		case err == nil && resp.ErrorStatus == 0:
			// ok
		case err == ErrReadTimeout:
			if try >= c.Retries {
				break out
			}

			if try < c.Retries/2 && p.MaxRepetitions > 4 {
				p.MaxRepetitions /= 2
			} else if p.Version == Version2c {
				p.Version = Version1
				p.Command = GetNext
			}

			try++
			continue
		case err != nil:
			break out
		case resp.ErrorStatus == NoSuchNameError:
			if len(resp.Vars) > 1 {
				log.Printf("some vars are probably lost\n%v", resp.Dump())
			}
			break out
		case resp.ErrorStatus == TooBigError && p.MaxRepetitions > 1:
			p.MaxRepetitions /= 2
			continue
		default:
			err = fmt.Errorf("SNMP error: %d (%d)", resp.ErrorStatus, resp.ErrorIndex)
			break out
		}

		if len(resp.Vars) == 0 {
			break
		}

		for _, v := range resp.Vars {
			if v.Type == EndOfMIBView {
				break out
			}

			if !v.ObjectID.HasPrefix(root) {
				break out
			}

			vars = append(vars, v)
		}

		last := resp.Vars[len(resp.Vars)-1]
		obj = last.ObjectID
		try = 0
	}

	if t != nil {
		t.Duration = time.Since(start)
	}

	if err != nil {
		if resp == nil {
			resp = p
			resp.Vars = nil
		}
		resp.Vars = append(vars, resp.Vars...)
		resp.NonRepeaters = p.NonRepeaters
		resp.MaxRepetitions = p.MaxRepetitions
		return resp, err
	}

	resp.Vars = vars
	resp.NonRepeaters = p.NonRepeaters
	resp.MaxRepetitions = p.MaxRepetitions

	return resp, nil
}

// Run does background tasks reqiured for work.
// It's blocked until Client Closed
func (c *Client) Run() {
	buf := make([]byte, 0x10000)
	for {
		err := c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if err != nil {
			log.Printf("SetDeadline: %v", err)
		}

		n, addr, err := c.conn.ReadFrom(buf)
		select {
		case <-c.stopc:
			c.closeAllRequests(err)
			return
		default:
		}
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			log.Printf("conn.Read: %v %v", err, err)
			continue
		}

		p := new(PDU)
		err = p.Decode(buf[:n])

		c.mu.Lock()
		rc := c.reqs[p.ReqID]
		c.mu.Unlock()

		//	log.Printf("Read packet ver %v from %v id %x err-st %d vars %d err %v bytes %d", p.Version, addr, p.ReqID, p.ErrorStatus, len(p.Vars), err, n)

		if rc == nil {
			select {
			case c.Receive <- Packet{Addr: addr, PDU: p, Err: err}:
			default:
			}

			continue
		}

		select {
		case rc <- Packet{
			Addr: addr,
			PDU:  p,
			Err:  err,
		}:
		default:
			log.Printf("packet dropped: from %20v, id %8x, err %v", addr, p.ReqID, err)
		}
	}
}

func (c *Client) closeAllRequests(err error) {
	if err == nil {
		err = ErrClosed
	}
	c.mu.Lock()
	for _, rc := range c.reqs {
		rc <- Packet{Err: err}
	}
	c.mu.Unlock()
}

// Close stops Run and closes connection
func (c *Client) Close() error {
	close(c.stopc)
	return c.conn.Close()
}

func Dumper(conn net.PacketConn) error {
	buf := make([]byte, 0x10000)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}

		p := new(PDU)
		err = p.Decode(buf[:n])
		if err != nil {
			log.Printf("decode: %v", err)
		}

		log.Printf("pdu from %v:\n%v", addr, p.Dump())
	}

	return nil
}

// EncodeTo encodes Protocol Data Unit to buffer.
// If buffer is nil or not big enough new buffer is allocated.
func (p *PDU) EncodeTo(b []byte) []byte {
	return asn1.BuildSequence(b, asn1.Sequence|asn1.Constructor, func(b []byte) []byte {
		b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, int(p.Version))
		b = asn1.BuildString(b, asn1.Universal|asn1.Primitive|asn1.OctetString, p.Community)

		b = asn1.BuildSequence(b, p.Command, func(b []byte) []byte {
			b = asn1.BuildInt32(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.ReqID)

			switch p.Command {
			case GetBulk:
				b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.NonRepeaters)
				b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.MaxRepetitions)
			default:
				b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.ErrorStatus)
				b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.ErrorIndex)
			}

			b = asn1.BuildSequence(b, asn1.Sequence|asn1.Constructor, func(b []byte) []byte {
				for _, v := range p.Vars {
					b = v.EncodeTo(b)
				}
				return b
			})
			return b
		})
		return b
	})
}

// Decode decodes Protocol Data Unit from the buffer
func (p *PDU) Decode(b []byte) (err error) {
	b, err = asn1.ParseSequence(b, func(tp asn1.Type, b []byte) (err error) {
		b, _, v := asn1.ParseInt(b)
		p.Version = Version(v)
		b, _, p.Community = asn1.ParseString(b)

		b, err = asn1.ParseSequence(b, func(tp asn1.Type, b []byte) (err error) {
			p.Command = tp

			b, _, p.ReqID = asn1.ParseInt32(b)

			switch p.Command {
			case GetBulk:
				b, _, p.NonRepeaters = asn1.ParseInt(b)
				b, _, p.MaxRepetitions = asn1.ParseInt(b)
			default:
				b, _, p.ErrorStatus = asn1.ParseInt(b)
				b, _, p.ErrorIndex = asn1.ParseInt(b)
			}

			b, err = asn1.ParseSequence(b, func(tp asn1.Type, b []byte) error {
				for len(b) > 0 {
					var v Var
					b, err = v.Decode(b)
					if err != nil {
						return err
					}

					p.Vars = append(p.Vars, v)
				}

				return nil
			})
			if err != nil {
				return err
			}
			if len(b) != 0 {
				return ErrExtraData
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(b) != 0 {
			return ErrExtraData
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(b) != 0 {
		return ErrExtraData
	}

	return nil
}

// EncodeTo encodes Variable to buffer.
// If buffer is nil or not big enough new buffer is allocated.
func (v *Var) EncodeTo(b []byte) []byte {
	return asn1.BuildSequence(b, asn1.Sequence|asn1.Constructor, func(b []byte) []byte {
		b = asn1.BuildObjectID(b, asn1.ObjectID, v.ObjectID)
		switch v.Type {
		case asn1.Null:
			b = asn1.BuildNull(b, v.Type)
		case asn1.Integer:
			b = asn1.BuildInt(b, v.Type, v.Value.(int))
		case asn1.OctetString:
			b = asn1.BuildString(b, v.Type, v.Value.(string))
		default:
			panic(v.Type)
		}
		return b
	})
}

// Decode decodes Variable from the buffer
func (v *Var) Decode(b []byte) ([]byte, error) {
	return asn1.ParseSequence(b, func(_ asn1.Type, b []byte) error {
		b, _, obj := asn1.ParseObjectID(b)
		v.ObjectID = obj

		_, tp, _ := asn1.ParseHeader(b)

		switch tp {
		case asn1.Integer, Counter, Counter64, Gauge:
			b, v.Type, v.Value = asn1.ParseInt(b)
		case Timeticks:
			var tk int64
			b, v.Type, tk = asn1.ParseInt64(b)
			v.Value = time.Second / 100 * time.Duration(tk)
		case asn1.OctetString:
			b, v.Type, v.Value = asn1.ParseString(b)
		case asn1.ObjectID:
			b, v.Type, v.Value = asn1.ParseObjectID(b)
		case IPAddress:
			var r []byte
			b, v.Type, r = asn1.ParseRaw(b)
			v.Value = net.IP(r)
		case Null:
			b, v.Type, _ = asn1.ParseRaw(b)
		default:
			b, v.Type, v.Value = asn1.ParseRaw(b)
		}

		if len(b) != 0 {
			return ErrExtraData
		}

		return nil
	})
}

func (p *PDU) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ver %2v community %v cmd %v reqid %x ", p.Version, p.Community, CommandString(p.Command), p.ReqID)
	switch p.Command {
	case GetBulk:
		fmt.Fprintf(&b, "non-rep %d max-rep %d", p.NonRepeaters, p.MaxRepetitions)
	default:
		fmt.Fprintf(&b, "err-status %d err-index %d", p.ErrorStatus, p.ErrorIndex)
	}
	fmt.Fprintf(&b, " vars %d", len(p.Vars))
	//	b.WriteByte('\n')
	//	for _, v := range p.Vars {
	//		b.WriteString(v.String())
	//		b.WriteByte('\n')
	//	}

	return b.String()
}

// Dump returns Protocol Data Unit header info and all Variables
func (p *PDU) Dump() string {
	var b strings.Builder
	b.WriteString(p.String())
	b.WriteByte('\n')
	for _, v := range p.Vars {
		b.WriteString(v.String())
		b.WriteByte('\n')
	}

	return b.String()
}

func (v Var) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%-30v tp %-12v : ", v.ObjectID, TypeString(v.Type))
	switch v.Type {
	case asn1.OctetString:
		fmt.Fprintf(&b, "%q", v.Value)
	default:
		fmt.Fprintf(&b, "%v", v.Value)
	}

	return b.String()
}

func (v Version) String() string {
	switch v {
	case Version1:
		return "1"
	case Version2c:
		return "2c" //nolint:goconst
	case Version3:
		return "3"
	default:
		return fmt.Sprintf("%d", int(v))
	}
}

// TypeString formats Type as a string
func TypeString(t Type) string {
	if t&0xc0 == 0 {
		return t.String()
	}
	v, ok := map[asn1.Type]string{
		IPAddress:      "IPAddress",
		Counter:        "Counter",
		Gauge:          "Gauge",
		Timeticks:      "Timeticks",
		Opaque:         "Opaque",
		Counter64:      "Counter64",
		Float:          "Float",
		Double:         "Double",
		Integer64:      "Integer64",
		Unsigned64:     "Unsigned64",
		NoSuchObject:   "NoSuchObject",
		NoSuchInstance: "NoSuchInstance",
		EndOfMIBView:   "EndOfMIBView",
	}[t]
	if ok {
		return v
	}
	return fmt.Sprintf("Type[%x]", int(t))
}

// CommandString formats Command as a string
func CommandString(t Command) string {
	v, ok := map[asn1.Type]string{
		Get:      "Get",
		GetNext:  "GetNext",
		Response: "Response",
		Set:      "Set",
		Trap:     "Trap",
		GetBulk:  "GetBulk",
	}[t]
	if ok {
		return v
	}
	return fmt.Sprintf("Command[%x]", int(t))
}

func ParseVersion(s string) (Version, error) {
	switch s {
	case "1":
		return Version1, nil
	case "2c":
		return Version2c, nil
	case "3":
		return Version3, nil
	default:
		return 0, errors.New("unsupported version")
	}
}
