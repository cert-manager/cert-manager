/* // +build testing */

// Copyright (c) 2012-2018 Ugorji Nwoke. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package codec

// This file contains values used by tests and benchmarks.
// The benchmarks will test performance against other libraries
// (encoding/json, json-iterator, bson, gob, etc).
// Consequently, we only use values that will parse well in all engines,
// and only leverage features that work across multiple libraries for a truer comparison.
// For example,
// - JSON/BSON do not like maps with keys that are not strings,
//   so we only use maps with string keys here.
// - _struct options are not honored by other libraries,
//   so we don't use them in this file.

import (
	"math"
	"strings"
)

// func init() {
// 	rt := reflect.TypeOf((*TestStruc)(nil)).Elem()
// 	defTypeInfos.get(rt2id(rt), rt)
// }

type wrapSliceUint64 []uint64
type wrapSliceString []string
type wrapUint64 uint64
type wrapString string
type wrapUint64Slice []wrapUint64
type wrapStringSlice []wrapString

type stringUint64T struct {
	S string
	U uint64
}

type AnonInTestStruc struct {
	AS         string
	AI64       int64
	AI16       int16
	AUi64      uint64
	ASslice    []string
	AI64slice  []int64
	AUi64slice []uint64
	AF64slice  []float64
	AF32slice  []float32

	// AMI32U32  map[int32]uint32
	// AMU32F64 map[uint32]float64 // json/bson do not like it
	AMSU16 map[string]uint16

	// use these to test 0-len or nil slices/maps/arrays
	AI64arr0    [0]int64
	A164slice0  []int64
	AUi64sliceN []uint64
	AMSU16N     map[string]uint16
	AMSU16E     map[string]uint16
}

// testSimpleFields is a sub-set of TestStrucCommon
type testSimpleFields struct {
	S string

	I64 int64
	I8  int8

	Ui64 uint64
	Ui8  uint8

	F64 float64
	F32 float32

	B bool

	Sslice    []string
	I16slice  []int16
	Ui64slice []uint64
	Ui8slice  []uint8
	Bslice    []bool

	Iptrslice []*int64

	WrapSliceInt64  wrapSliceUint64
	WrapSliceString wrapSliceString

	Msi64 map[string]int64
}

type TestStrucCommon struct {
	S string

	I64 int64
	I32 int32
	I16 int16
	I8  int8

	I64n int64
	I32n int32
	I16n int16
	I8n  int8

	Ui64 uint64
	Ui32 uint32
	Ui16 uint16
	Ui8  uint8

	F64 float64
	F32 float32

	B  bool
	By uint8 // byte: msgp doesn't like byte

	Sslice    []string
	I64slice  []int64
	I16slice  []int16
	Ui64slice []uint64
	Ui8slice  []uint8
	Bslice    []bool
	Byslice   []byte

	Iptrslice []*int64

	WrapSliceInt64  wrapSliceUint64
	WrapSliceString wrapSliceString

	Msi64 map[string]int64

	Simplef testSimpleFields

	SstrUi64T []stringUint64T

	AnonInTestStruc

	NotAnon AnonInTestStruc

	// R          Raw // Testing Raw must be explicitly turned on, so use standalone test
	// Rext RawExt // Testing RawExt is tricky, so use standalone test

	Nmap   map[string]bool //don't set this, so we can test for nil
	Nslice []byte          //don't set this, so we can test for nil
	Nint64 *int64          //don't set this, so we can test for nil
}

type TestStruc struct {
	// _struct struct{} `json:",omitempty"` //set omitempty for every field

	TestStrucCommon

	Mtsptr     map[string]*TestStruc
	Mts        map[string]TestStruc
	Its        []*TestStruc
	Nteststruc *TestStruc
}

func populateTestStrucCommon(ts *TestStrucCommon, n int, bench, useInterface, useStringKeyOnly bool) {
	var i64a, i64b, i64c, i64d int64 = 64, 6464, 646464, 64646464

	// if bench, do not use uint64 values > math.MaxInt64, as bson, etc cannot decode them

	var a = AnonInTestStruc{
		// There's more leeway in altering this.
		AS:    strRpt(n, "A-String"),
		AI64:  -64646464,
		AI16:  1616,
		AUi64: 64646464,
		// (U+1D11E)G-clef character may be represented in json as "\uD834\uDD1E".
		// single reverse solidus character may be represented in json as "\u005C".
		// include these in ASslice below.
		ASslice: []string{
			strRpt(n, "Aone"),
			strRpt(n, "Atwo"),
			strRpt(n, "Athree"),
			strRpt(n, "Afour.reverse_solidus.\u005c"),
			strRpt(n, "Afive.Gclef.\U0001d11E\"ugorji\"done.")},
		AI64slice: []int64{
			0, 1, -1, -22, 333, -4444, 55555, -666666,
			// msgpack ones
			-48, -32, -24, -8, 32, 127, 192, 255,
			// standard ones
			0, -1, 1,
			math.MaxInt8, math.MaxInt8 + 4, math.MaxInt8 - 4,
			math.MaxInt16, math.MaxInt16 + 4, math.MaxInt16 - 4,
			math.MaxInt32, math.MaxInt32 + 4, math.MaxInt32 - 4,
			math.MaxInt64, math.MaxInt64 - 4,
			math.MinInt8, math.MinInt8 + 4, math.MinInt8 - 4,
			math.MinInt16, math.MinInt16 + 4, math.MinInt16 - 4,
			math.MinInt32, math.MinInt32 + 4, math.MinInt32 - 4,
			math.MinInt64, math.MinInt64 + 4,
		},
		AUi64slice: []uint64{
			0, 1, 22, 333, 4444, 55555, 666666,
			// standard ones
			math.MaxUint8, math.MaxUint8 + 4, math.MaxUint8 - 4,
			math.MaxUint16, math.MaxUint16 + 4, math.MaxUint16 - 4,
			math.MaxUint32, math.MaxUint32 + 4, math.MaxUint32 - 4,
		},
		AMSU16: map[string]uint16{strRpt(n, "1"): 1, strRpt(n, "22"): 2, strRpt(n, "333"): 3, strRpt(n, "4444"): 4},

		// Note: +/- inf, NaN, and other non-representable numbers should not be explicitly tested here

		AF64slice: []float64{
			11.11e-11, -11.11e+11,
			2.222E+12, -2.222E-12,
			-555.55E-5, 555.55E+5,
			666.66E-6, -666.66E+6,
			7777.7777E-7, -7777.7777E-7,
			-8888.8888E+8, 8888.8888E+8,
			-99999.9999E+9, 99999.9999E+9,
			// these below are hairy enough to need strconv.ParseFloat
			33.33E-33, -33.33E+33,
			44.44e+44, -44.44e-44,
			// standard ones
			0, -1, 1,
			// math.Inf(1), math.Inf(-1),
			math.Pi, math.Phi, math.E,
			math.MaxFloat64, math.SmallestNonzeroFloat64,
		},
		AF32slice: []float32{
			11.11e-11, -11.11e+11,
			2.222E+12, -2.222E-12,
			-555.55E-5, 555.55E+5,
			666.66E-6, -666.66E+6,
			7777.7777E-7, -7777.7777E-7,
			-8888.8888E+8, 8888.8888E+8,
			-99999.9999E+9, 99999.9999E+9,
			// these below are hairy enough to need strconv.ParseFloat
			33.33E-33, -33.33E+33,
			// standard ones
			0, -1, 1,
			// math.Float32frombits(0x7FF00000), math.Float32frombits(0xFFF00000), //+inf and -inf
			math.MaxFloat32, math.SmallestNonzeroFloat32,
		},

		A164slice0:  []int64{},
		AUi64sliceN: nil,
		AMSU16N:     nil,
		AMSU16E:     map[string]uint16{},
	}

	if !bench {
		a.AUi64slice = append(a.AUi64slice, math.MaxUint64, math.MaxUint64-4)
	}
	*ts = TestStrucCommon{
		S: strRpt(n, `some really really cool names that are nigerian and american like "ugorji melody nwoke" - get it? `),

		// set the numbers close to the limits
		I8:   math.MaxInt8 * 2 / 3,  // 8,
		I8n:  math.MinInt8 * 2 / 3,  // 8,
		I16:  math.MaxInt16 * 2 / 3, // 16,
		I16n: math.MinInt16 * 2 / 3, // 16,
		I32:  math.MaxInt32 * 2 / 3, // 32,
		I32n: math.MinInt32 * 2 / 3, // 32,
		I64:  math.MaxInt64 * 2 / 3, // 64,
		I64n: math.MinInt64 * 2 / 3, // 64,

		Ui64: math.MaxUint64 * 2 / 3, // 64
		Ui32: math.MaxUint32 * 2 / 3, // 32
		Ui16: math.MaxUint16 * 2 / 3, // 16
		Ui8:  math.MaxUint8 * 2 / 3,  // 8

		F32: 3.402823e+38, // max representable float32 without losing precision
		F64: 3.40281991833838838338e+53,

		B:  true,
		By: 5,

		Sslice:    []string{strRpt(n, "one"), strRpt(n, "two"), strRpt(n, "three")},
		I64slice:  []int64{1111, 2222, 3333},
		I16slice:  []int16{44, 55, 66},
		Ui64slice: []uint64{12121212, 34343434, 56565656},
		Ui8slice:  []uint8{210, 211, 212},
		Bslice:    []bool{true, false, true, false},
		Byslice:   []byte{13, 14, 15},

		Msi64: map[string]int64{
			strRpt(n, "one"):       1,
			strRpt(n, "two"):       2,
			strRpt(n, "\"three\""): 3,
		},

		WrapSliceInt64:  []uint64{4, 16, 64, 256},
		WrapSliceString: []string{strRpt(n, "4"), strRpt(n, "16"), strRpt(n, "64"), strRpt(n, "256")},

		// R: Raw([]byte("goodbye")),
		// Rext: RawExt{ 120, []byte("hello"), }, // TODO: don't set this - it's hard to test

		// DecodeNaked bombs here, because the stringUint64T is decoded as a map,
		// and a map cannot be the key type of a map.
		// Thus, don't initialize this here.
		// Msu2wss: map[stringUint64T]wrapStringSlice{
		// 	{"5", 5}: []wrapString{"1", "2", "3", "4", "5"},
		// 	{"3", 3}: []wrapString{"1", "2", "3"},
		// },

		// make Simplef same as top-level
		// TODO: should this have slightly different values???
		Simplef: testSimpleFields{
			S: strRpt(n, `some really really cool names that are nigerian and american like "ugorji melody nwoke" - get it? `),

			// set the numbers close to the limits
			I8:  math.MaxInt8 * 2 / 3,  // 8,
			I64: math.MaxInt64 * 2 / 3, // 64,

			Ui64: math.MaxUint64 * 2 / 3, // 64
			Ui8:  math.MaxUint8 * 2 / 3,  // 8

			F32: 3.402823e+38, // max representable float32 without losing precision
			F64: 3.40281991833838838338e+53,

			B: true,

			Sslice:    []string{strRpt(n, "one"), strRpt(n, "two"), strRpt(n, "three")},
			I16slice:  []int16{44, 55, 66},
			Ui64slice: []uint64{12121212, 34343434, 56565656},
			Ui8slice:  []uint8{210, 211, 212},
			Bslice:    []bool{true, false, true, false},

			Msi64: map[string]int64{
				strRpt(n, "one"):       1,
				strRpt(n, "two"):       2,
				strRpt(n, "\"three\""): 3,
			},

			WrapSliceInt64:  []uint64{4, 16, 64, 256},
			WrapSliceString: []string{strRpt(n, "4"), strRpt(n, "16"), strRpt(n, "64"), strRpt(n, "256")},
		},

		SstrUi64T:       []stringUint64T{{"1", 1}, {"2", 2}, {"3", 3}, {"4", 4}},
		AnonInTestStruc: a,
		NotAnon:         a,
	}

	if bench {
		ts.Ui64 = math.MaxInt64 * 2 / 3
		ts.Simplef.Ui64 = ts.Ui64
	}

	//For benchmarks, some things will not work.
	if !bench {
		//json and bson require string keys in maps
		//ts.M = map[interface{}]interface{}{
		//	true: "true",
		//	int8(9): false,
		//}
		//gob cannot encode nil in element in array (encodeArray: nil element)
		ts.Iptrslice = []*int64{nil, &i64a, nil, &i64b, nil, &i64c, nil, &i64d, nil}
		// ts.Iptrslice = nil
	}
	if !useStringKeyOnly {
		// ts.AnonInTestStruc.AMU32F64 = map[uint32]float64{1: 1, 2: 2, 3: 3} // Json/Bson barf
	}
}

func newTestStruc(depth, n int, bench, useInterface, useStringKeyOnly bool) (ts *TestStruc) {
	ts = &TestStruc{}
	populateTestStrucCommon(&ts.TestStrucCommon, n, bench, useInterface, useStringKeyOnly)
	if depth > 0 {
		depth--
		if ts.Mtsptr == nil {
			ts.Mtsptr = make(map[string]*TestStruc)
		}
		if ts.Mts == nil {
			ts.Mts = make(map[string]TestStruc)
		}
		ts.Mtsptr[strRpt(n, "0")] = newTestStruc(depth, n, bench, useInterface, useStringKeyOnly)
		ts.Mts[strRpt(n, "0")] = *(ts.Mtsptr[strRpt(n, "0")])
		ts.Its = append(ts.Its, ts.Mtsptr[strRpt(n, "0")])
	}
	return
}

var testStrRptMap = make(map[int]map[string]string)

func strRpt(n int, s string) string {
	if false {
		// fmt.Printf(">>>> calling strings.Repeat on n: %d, key: %s\n", n, s)
		return strings.Repeat(s, n)
	}
	m1, ok := testStrRptMap[n]
	if !ok {
		// fmt.Printf(">>>> making new map for n: %v\n", n)
		m1 = make(map[string]string)
		testStrRptMap[n] = m1
	}
	v1, ok := m1[s]
	if !ok {
		// fmt.Printf(">>>> creating new entry for key: %s\n", s)
		v1 = strings.Repeat(s, n)
		m1[s] = v1
	}
	return v1
}

// func wstrRpt(n int, s string) wrapBytes {
// 	 return wrapBytes(bytes.Repeat([]byte(s), n))
// }
