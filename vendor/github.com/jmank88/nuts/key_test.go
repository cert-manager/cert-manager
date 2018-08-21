package nuts

import (
	"bytes"
	"strconv"
	"testing"
)

func TestKeyLen(t *testing.T) {
	for _, test := range []struct {
		x   uint64
		exp int
	}{
		{0, 1},
		{1, 1},
		{1 << 8, 2},
		{1 << 16, 3},
		{1 << 24, 4},
		{1 << 32, 5},
		{1 << 40, 6},
		{1 << 48, 7},
		{1 << 56, 8},
	} {
		got := KeyLen(test.x)
		if got != test.exp {
			t.Errorf("%d: expected length %d but got %d", test.x, test.exp, got)
		}
	}
}

func TestKey(t *testing.T) {
	for _, test := range []struct {
		max int
		xs  []uint64
		bs  [][]byte
	}{
		{
			max: 1 << 7,
			xs:  []uint64{0, 1, (1 << 8) - 1},
			bs: [][]byte{
				{0x00}, {0x01}, {0xFF},
			},
		},
		{
			max: 1 << 15,
			xs:  []uint64{0, 1, (1 << 16) - 1},
			bs: [][]byte{
				{0x00, 0x00}, {0x00, 0x01}, {0xFF, 0xFF},
			},
		},
		{
			max: 1 << 23,
			xs:  []uint64{0, 1, (1 << 24) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00}, {0x00, 0x00, 0x01}, {0xFF, 0xFF, 0xFF},
			},
		},
		{
			max: 1 << 31,
			xs:  []uint64{0, 1, (1 << 32) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x01},
				{0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			max: 1 << 39,
			xs:  []uint64{0, 1, (1 << 40) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x01},
				{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			max: 1 << 47,
			xs:  []uint64{0, 1, (1 << 48) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			max: 1 << 55,
			xs:  []uint64{0, 1, (1 << 56) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			max: 1 << 60,
			xs:  []uint64{0, 1, (1 << 60) - 1},
			bs: [][]byte{
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				{0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
	} {
		t.Run(strconv.Itoa(test.max), func(t *testing.T) {
			k := make(Key, KeyLen(uint64(test.max)))
			for i, x := range test.xs {
				k.Put(x)
				if !bytes.Equal(k, test.bs[i]) {
					t.Errorf("unexpected serialized integer %d:\n\t(GOT): %#x\n\t(WNT): %#x", x, k, test.bs[i])
				}
			}
		})
	}
}
