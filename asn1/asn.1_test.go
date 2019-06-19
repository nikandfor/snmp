package asn1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSequence(t *testing.T) {
	b := BuildSequence(nil, 0x30, func(b []byte) []byte {
		return BuildInt(b, Integer, 5)
	})
	assert.Equal(t, []byte{0x30, 3, 2, 1, 5}, b)

	inside := false
	ParseSequence(b, func(tp Type, b []byte) error {
		assert.Equal(t, Type(0x30), tp)
		b, itp, v := ParseInt(b)
		assert.Empty(t, b)
		assert.Equal(t, Type(0x2), itp)
		assert.Equal(t, 5, v)

		inside = true

		return nil
	})

	assert.True(t, inside)
}

func TestInt(t *testing.T) {
	b := BuildInt(nil, 0x11, 0x22)
	assert.Equal(t, []byte{0x11, 0x1, 0x22}, b)
}

func TestString(t *testing.T) {
	b := BuildString(nil, 0x11, "str_val")
	assert.Equal(t, append([]byte{0x11, 0x7}, "str_val"...), b)
}
