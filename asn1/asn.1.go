package asn1

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
)

type (
	// Type is an ASN.1 type
	Type int

	// OID is as ASN.1 Object ID
	OID []int
)

//go:generate stringer -type Type .

const ( // Types
	Boolean     Type = 0x1
	Integer     Type = 0x2
	BitString   Type = 0x3
	OctetString Type = 0x4
	Null        Type = 0x5
	ObjectID    Type = 0x6
	Sequence    Type = 0x10
	Set         Type = 0x11
)

const (
	Universal   = 0x0
	Application = 0x40
	Context     = 0x80
	Private     = 0xc0
)

const (
	Primitive   = 0x0
	Constructor = 0x20
)

const (
	LongLen = 0x80
)

// BuildLength writes header and inserts length when data is written
func BuildLength(b []byte, cb func(b []byte) []byte) []byte {
	b = append(b, 0)
	st := len(b)
	b = cb(b)
	l := len(b) - st

	sz := 0
	switch {
	case l < 0x80:
		b[st-1] = byte(l)
		return b
	case l <= 0xff:
		sz = 1
		b = append(b, 0)
	case l <= 0xffff:
		sz = 2
		b = append(b, 0, 0)
	default:
		panic(l)
	}

	copy(b[st+sz:], b[st:])

	b[st-1] = byte(sz) | LongLen
	for i := 0; i < sz; i++ {
		b[i] = byte(l >> uint(sz-i-1) * 8)
	}

	return b
}

// BuildSequence writes ASN.1 sequence record
func BuildSequence(b []byte, tp Type, cb func([]byte) []byte) []byte {
	b = append(b, byte(tp))
	return BuildLength(b, cb)
}

// BuildInt64 writes ASN.1 integer type. The only difference between BuildInt* functions is argument type so that you may not cast
func BuildInt64(b []byte, tp Type, v int64) []byte {
	var sz int
	var q int64 = 0xff
	for sz = 1; sz <= 8; sz++ {
		if (v & ^q) == 0 {
			break
		}
		q = q<<8 | 0xff
	}

	b = append(b, byte(tp), byte(sz))
	for i := sz - 1; i >= 0; i-- {
		b = append(b, byte(v>>uint(8*i)))
	}
	return b
}

// BuildInt32 writes ASN.1 integer type. The only difference between BuildInt* functions is argument type so that you may not cast
func BuildInt32(b []byte, tp Type, v int32) []byte {
	var sz int
	var q int32 = 0xff
	for sz = 1; sz <= 8; sz++ {
		if (v & ^q) == 0 {
			break
		}
		q = q<<8 | 0xff
	}

	b = append(b, byte(tp), byte(sz))
	for i := sz - 1; i >= 0; i-- {
		b = append(b, byte(v>>uint(8*i)))
	}
	return b
}

// BuildInt writes ASN.1 integer type. The only difference between BuildInt* functions is argument type so that you may not cast
func BuildInt(b []byte, tp Type, v int) []byte { return BuildInt64(b, tp, int64(v)) }

// BuildString writes ASN.1 string type
func BuildString(b []byte, tp Type, s string) []byte {
	b = append(b, byte(tp))
	l := len(s)
	switch {
	case l < 0x80:
		b = append(b, byte(l))
	case l <= 0xff:
		b = append(b, 1|LongLen, byte(l))
	case l <= 0xffff:
		b = append(b, 2|LongLen, byte(l>>8), byte(l))
	default:
		panic(l)
	}
	b = append(b, s...)
	return b
}

// BuildObjectID writes ASN.1 Object ID
func BuildObjectID(b []byte, tp Type, id OID) []byte {
	// first two bytes encoded as byte(id[0] * 40 + id[1])
	l := 1
	for i := 2; i < len(id); i++ {
		q := id[i]
		switch {
		case q < 0x80:
			l++
		case q < 0x4000:
			l += 2
		case q < 0x200000:
			l += 3
		case q < 0x10000000:
			l += 4
		default:
			l += 5
		}
	}

	if l >= 0x80 {
		panic(l)
	}

	b = append(b, byte(tp), byte(l))

	switch {
	case len(id) == 0:
		return append(b, 0)
	case id[0] > 2:
		panic(id[0])
	case len(id) == 1:
		return append(b, byte(id[0]*40))
	case id[1] > 40:
		panic(id[1])
	default:
		b = append(b, byte(id[0]*40+id[1]))
	}

	for i := 2; i < len(id); i++ {
		q := id[i]
		switch {
		case q < 0x80:
			b = append(b, byte(q))
		case q < 0x4000:
			b = append(b, byte(q>>7)|0x80, byte(q)&0x7f)
		case q < 0x200000:
			b = append(b, byte(q>>14)|0x80, byte(q>>7)|0x80, byte(q)&0x7f)
		case q < 0x10000000:
			b = append(b, byte(q>>21)|0x80, byte(q>>14)|0x80, byte(q>>7)|0x80, byte(q)&0x7f)
		default:
			b = append(b, byte(q>>28)|0x80, byte(q>>21)|0x80, byte(q>>14)|0x80, byte(q>>7)|0x80, byte(q)&0x7f)
		}
	}

	return b
}

// BuildNull writes ASN.1 Null value
func BuildNull(b []byte, tp Type) []byte { return append(b, byte(tp), 0) }

// ParseHeader parses ASN.1 header: type and length.
// It returns (rest of buffer, type, record length).
func ParseHeader(b []byte) ([]byte, Type, int) {
	tp := Type(b[0])
	b, l := ParseLength(b[1:])
	return b, tp, l
}

// ParseLength parses ANS.1 length.
// It returns (rest of buffer, record length).
func ParseLength(b []byte) ([]byte, int) {
	if len(b) == 0 {
		return nil, 0
	}
	if b[0] < 0x80 {
		return b[1:], int(b[0])
	}
	if b[0]&LongLen != LongLen {
		return nil, int(b[0])
	}
	n := int(b[0] & 0xf)
	l := 0
	for i := 0; i < n; i++ {
		l <<= 8
		l |= int(b[1+i])
	}
	return b[1+n:], l
}

// ParseSequence parses ANS.1 sequence record.
// Type and length are parsed by function, record body is passed to callback.
// It returns (rest of buffer, error from callback).
func ParseSequence(b []byte, cb func(tp Type, b []byte) error) ([]byte, error) {
	b, tp, l := ParseHeader(b)
	err := cb(tp, b[:l])
	return b[l:], err
}

// ParseRaw parses any ANS.1 record.
// It returns (rest of buffer, type, record body).
func ParseRaw(b []byte) ([]byte, Type, []byte) {
	tp := Type(b[0])
	b, l := ParseLength(b[1:])
	res := b[:l]
	return b[l:], tp, res
}

// ParseInt64 parses ANS.1 integer record.
// The only difference between all ParseInt* functions is the result type.
// It returns (rest of buffer, type, int value).
func ParseInt64(b []byte) ([]byte, Type, int64) {
	tp := Type(b[0])
	n := int(b[1])
	v := int64(0)

	for i := 0; i < n; i++ {
		v <<= 8
		v |= int64(b[2+i])
	}

	return b[2+n:], tp, v
}

// ParseInt32 parses ANS.1 integer record.
// The only difference between all ParseInt* functions is the result type.
// It returns (rest of buffer, type, int value).
func ParseInt32(b []byte) ([]byte, Type, int32) {
	tp := Type(b[0])
	n := int(b[1])
	v := int32(0)

	for i := 0; i < n; i++ {
		v <<= 8
		v |= int32(b[2+i])
	}

	return b[2+n:], tp, v
}

// ParseInt parses ANS.1 integer record.
// The only difference between all ParseInt* functions is the result type.
// It returns (rest of buffer, type, int value).
func ParseInt(b []byte) ([]byte, Type, int) {
	b, tp, v := ParseInt64(b)
	return b, tp, int(v)
}

// ParseInt parses ANS.1 string record.
// It returns (rest of buffer, type, int value).
func ParseString(b []byte) ([]byte, Type, string) {
	tp := Type(b[0])
	var l int
	b, l = ParseLength(b[1:])
	v := string(b[:l])
	return b[l:], tp, v
}

// ParseObjectID parses ANS.1 object ID.
// It returns (rest of buffer, type, OID).
func ParseObjectID(b []byte) ([]byte, Type, OID) {
	tp := Type(b[0])
	var l int
	b, l = ParseLength(b[1:])
	v := OID{int(b[0]) / 40, int(b[0]) % 40}
	var buf int
	for i := 1; i < l; i++ {
		q := int(b[i])
		buf <<= 7
		buf |= q & 0x7f

		if q&0x80 == 0 {
			v = append(v, buf)
			buf = 0
		}
	}

	return b[l:], tp, v
}

// String formats Object ID as 1.3.6.1
func (o OID) String() string {
	var b bytes.Buffer
	for i, d := range o {
		if i != 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", d)
	}
	return b.String()
}

// HasPrefix checks if receiver is a parent Object ID of an argument
func (o OID) HasPrefix(p OID) bool {
	if len(o) < len(p) {
		return false
	}
	for i := range p {
		if o[i] != p[i] {
			return false
		}
	}

	return true
}

// ParseOID parses Object ID in format 1.3.6.1.2.1
func ParseOID(s string) OID {
	if s == "" {
		return OID{}
	}
	ns := strings.Split(s, ".")
	r := make(OID, len(ns))
	for i, n := range ns {
		v, err := strconv.ParseUint(n, 10, 32)
		if err != nil {
			log.Fatalf("oid[%d]: %v", i, err)
		}
		r[i] = int(v)
	}
	return r
}
