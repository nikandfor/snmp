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

	"github.com/nikandfor/snmp/asn1"
)

var (
	ErrReadTimeout = errors.New("timeout")
	ErrExtraData   = errors.New("extra data")
)

type (
	Command int
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
		ReqID   int64

		NonRepeaters, MaxRepetitions int

		ErrorStatus, ErrorIndex int

		Vars []Var
	}

	Client struct {
		conn net.PacketConn

		ReadTimeout time.Duration
		Retries     int

		Version   Version
		Community string

		NonRepeaters   int
		MaxRepetitions int

		mu    sync.Mutex
		reqid int64
		reqs  map[int64]chan Resp

		stopc chan struct{}
	}

	Resp struct {
		Addr net.Addr
		PDU  *PDU
		Err  error
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
	IPAddress  asn1.Type = asn1.Application | 0x0
	Counter    asn1.Type = asn1.Application | 0x1
	Gauge      asn1.Type = asn1.Application | 0x2
	Timeticks  asn1.Type = asn1.Application | 0x3
	Opaque     asn1.Type = asn1.Application | 0x4
	Counter64  asn1.Type = asn1.Application | 0x6
	Float      asn1.Type = asn1.Application | 0x8
	Double     asn1.Type = asn1.Application | 0x9
	Integer64  asn1.Type = asn1.Application | 0x10
	Unsigned64 asn1.Type = asn1.Application | 0x11

	NoSuchObject   asn1.Type = asn1.Context | asn1.Primitive | 0x0
	NoSuchInstance asn1.Type = asn1.Context | asn1.Primitive | 0x1
	EndOfMIBView   asn1.Type = asn1.Context | asn1.Primitive | 0x2
)

func NewClient(conn net.PacketConn) *Client {
	return &Client{
		conn:        conn,
		ReadTimeout: time.Second,
		reqid:       rand.Int63n(0x100000000),
		reqs:        make(map[int64]chan Resp),
		stopc:       make(chan struct{}),
	}
}

func (c *Client) Send(addr net.Addr, p *PDU) error {
	b := p.EncodeTo(nil)

	_, err := c.conn.WriteTo(b, addr)

	return err
}

func (c *Client) Call(addr net.Addr, p *PDU) (*PDU, error) {
	//	log.Printf("Call %v %+v", addr, p)

	rc := make(chan Resp, 1)

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

	err := c.Send(addr, p)
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

func (c *Client) Walk(addr net.Addr, root asn1.OID) (*PDU, error) {
	var res *PDU
	obj := root
out:
	for {
		p := &PDU{
			Version:        Version2c,
			Community:      c.Community,
			Command:        GetBulk,
			NonRepeaters:   c.NonRepeaters,
			MaxRepetitions: c.MaxRepetitions,
			Vars: []Var{
				{ObjectID: obj, Type: asn1.Null},
			},
		}

		try := 0

		resp, err := c.Call(addr, p)
		if err != nil {
			if err == ErrReadTimeout && try < c.Retries {
				try++
				continue
			}
			return nil, err
		}
		if resp.ErrorStatus != 0 {
			return nil, fmt.Errorf("SNMP error: %d/%d", resp.ErrorStatus, resp.ErrorIndex)
		}

		//	log.Printf("resp: %v", resp)

		if res == nil {
			cp := *resp
			res = &cp
			res.Vars = nil
		}

		if len(resp.Vars) == 0 {
			break
		}

		for _, v := range resp.Vars {
			switch v.Type {
			case EndOfMIBView:
				break out
			}

			if !v.ObjectID.HasPrefix(root) {
				break out
			}

			res.Vars = append(res.Vars, v)
		}

		last := resp.Vars[len(resp.Vars)-1]
		obj = last.ObjectID
	}

	return res, nil
}

func (c *Client) Run() {
	buf := make([]byte, 0x10000)
	for {
		n, addr, err := c.conn.ReadFrom(buf[:])
		if err != nil {
			log.Printf("conn.Read: %v", err)
			continue
		}

		p := new(PDU)
		err = p.Decode(buf[:n])

		c.mu.Lock()
		rc := c.reqs[p.ReqID]
		c.mu.Unlock()

		//	log.Printf("Read packet from %v id %x err-st %d vars %d err %v bytes %d", addr, p.ReqID, p.ErrorStatus, len(p.Vars), err, n)

		if rc == nil {
			continue
		}

		select {
		case rc <- Resp{
			Addr: addr,
			PDU:  p,
			Err:  err,
		}:
		default:
			log.Printf("packet dropped: from %20v, id %8x, err %v", addr, p.ReqID, err)
		}
	}
}

func (p *PDU) EncodeTo(b []byte) []byte {
	return asn1.BuildSequence(b, asn1.Sequence|asn1.Constructor, func(b []byte) []byte {
		b = asn1.BuildInt(b, asn1.Universal|asn1.Primitive|asn1.Integer, (int)(p.Version))
		b = asn1.BuildString(b, asn1.Universal|asn1.Primitive|asn1.OctetString, p.Community)

		b = asn1.BuildSequence(b, asn1.Type(p.Command), func(b []byte) []byte {
			b = asn1.BuildInt64(b, asn1.Universal|asn1.Primitive|asn1.Integer, p.ReqID)

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

func (p *PDU) Decode(b []byte) (err error) {
	b, err = asn1.ParseSequence(b, func(tp asn1.Type, b []byte) (err error) {
		b, _, v := asn1.ParseInt(b)
		p.Version = Version(v)
		b, _, p.Community = asn1.ParseString(b)

		b, err = asn1.ParseSequence(b, func(tp asn1.Type, b []byte) (err error) {
			p.Command = Command(tp)

			b, _, p.ReqID = asn1.ParseInt64(b)

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
		default:
			b, v.Type, v.Value = asn1.ParseRaw(b)
		}

		return nil
	})
}

func (p *PDU) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ver %2v community %v cmd %v reqid %x ", p.Version, p.Community, p.Command, p.ReqID)
	switch p.Command {
	case GetBulk:
		fmt.Fprintf(&b, "non-rep %d max-rep %d", p.NonRepeaters, p.MaxRepetitions)
	default:
		fmt.Fprintf(&b, "err-status %d err-index %d", p.ErrorStatus, p.ErrorIndex)
	}
	fmt.Fprintf(&b, " vars %d\n", len(p.Vars))
	//	for _, v := range p.Vars {
	//		b.WriteString(v.String())
	//		b.WriteByte('\n')
	//	}

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
		return "2c"
	case Version3:
		return "3"
	default:
		return fmt.Sprintf("%d", (int)(v))
	}
}

func TypeString(t asn1.Type) string {
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