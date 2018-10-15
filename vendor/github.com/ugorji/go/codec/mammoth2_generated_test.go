// +build !notfastpath

// Copyright (c) 2012-2015 Ugorji Nwoke. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

// Code generated from mammoth2-test.go.tmpl - DO NOT EDIT.

package codec

// Increase codecoverage by covering all the codecgen paths, in fast-path and gen-helper.go....
//
// Add:
// - test file for creating a mammoth generated file as _mammoth_generated.go
//   - generate a second mammoth files in a different file: mammoth2_generated_test.go
//     - mammoth-test.go.tmpl will do this
//   - run codecgen on it, into mammoth2_codecgen_generated_test.go (no build tags)
//   - as part of TestMammoth, run it also
//   - this will cover all the codecgen, gen-helper, etc in one full run
//   - check in mammoth* files into github also
// - then
//
// Now, add some types:
//  - some that implement BinaryMarshal, TextMarshal, JSONMarshal, and one that implements none of it
//  - create a wrapper type that includes TestMammoth2, with it in slices, and maps, and the custom types
//  - this wrapper object is what we work encode/decode (so that the codecgen methods are called)

// import "encoding/binary"
import "fmt"

type TestMammoth2 struct {
	FIntf       interface{}
	FptrIntf    *interface{}
	FString     string
	FptrString  *string
	FFloat32    float32
	FptrFloat32 *float32
	FFloat64    float64
	FptrFloat64 *float64
	FUint       uint
	FptrUint    *uint
	FUint8      uint8
	FptrUint8   *uint8
	FUint16     uint16
	FptrUint16  *uint16
	FUint32     uint32
	FptrUint32  *uint32
	FUint64     uint64
	FptrUint64  *uint64
	FUintptr    uintptr
	FptrUintptr *uintptr
	FInt        int
	FptrInt     *int
	FInt8       int8
	FptrInt8    *int8
	FInt16      int16
	FptrInt16   *int16
	FInt32      int32
	FptrInt32   *int32
	FInt64      int64
	FptrInt64   *int64
	FBool       bool
	FptrBool    *bool

	FSliceIntf       []interface{}
	FptrSliceIntf    *[]interface{}
	FSliceString     []string
	FptrSliceString  *[]string
	FSliceFloat32    []float32
	FptrSliceFloat32 *[]float32
	FSliceFloat64    []float64
	FptrSliceFloat64 *[]float64
	FSliceUint       []uint
	FptrSliceUint    *[]uint
	FSliceUint8      []uint8
	FptrSliceUint8   *[]uint8
	FSliceUint16     []uint16
	FptrSliceUint16  *[]uint16
	FSliceUint32     []uint32
	FptrSliceUint32  *[]uint32
	FSliceUint64     []uint64
	FptrSliceUint64  *[]uint64
	FSliceUintptr    []uintptr
	FptrSliceUintptr *[]uintptr
	FSliceInt        []int
	FptrSliceInt     *[]int
	FSliceInt8       []int8
	FptrSliceInt8    *[]int8
	FSliceInt16      []int16
	FptrSliceInt16   *[]int16
	FSliceInt32      []int32
	FptrSliceInt32   *[]int32
	FSliceInt64      []int64
	FptrSliceInt64   *[]int64
	FSliceBool       []bool
	FptrSliceBool    *[]bool

	FMapIntfIntf          map[interface{}]interface{}
	FptrMapIntfIntf       *map[interface{}]interface{}
	FMapIntfString        map[interface{}]string
	FptrMapIntfString     *map[interface{}]string
	FMapIntfUint          map[interface{}]uint
	FptrMapIntfUint       *map[interface{}]uint
	FMapIntfUint8         map[interface{}]uint8
	FptrMapIntfUint8      *map[interface{}]uint8
	FMapIntfUint16        map[interface{}]uint16
	FptrMapIntfUint16     *map[interface{}]uint16
	FMapIntfUint32        map[interface{}]uint32
	FptrMapIntfUint32     *map[interface{}]uint32
	FMapIntfUint64        map[interface{}]uint64
	FptrMapIntfUint64     *map[interface{}]uint64
	FMapIntfUintptr       map[interface{}]uintptr
	FptrMapIntfUintptr    *map[interface{}]uintptr
	FMapIntfInt           map[interface{}]int
	FptrMapIntfInt        *map[interface{}]int
	FMapIntfInt8          map[interface{}]int8
	FptrMapIntfInt8       *map[interface{}]int8
	FMapIntfInt16         map[interface{}]int16
	FptrMapIntfInt16      *map[interface{}]int16
	FMapIntfInt32         map[interface{}]int32
	FptrMapIntfInt32      *map[interface{}]int32
	FMapIntfInt64         map[interface{}]int64
	FptrMapIntfInt64      *map[interface{}]int64
	FMapIntfFloat32       map[interface{}]float32
	FptrMapIntfFloat32    *map[interface{}]float32
	FMapIntfFloat64       map[interface{}]float64
	FptrMapIntfFloat64    *map[interface{}]float64
	FMapIntfBool          map[interface{}]bool
	FptrMapIntfBool       *map[interface{}]bool
	FMapStringIntf        map[string]interface{}
	FptrMapStringIntf     *map[string]interface{}
	FMapStringString      map[string]string
	FptrMapStringString   *map[string]string
	FMapStringUint        map[string]uint
	FptrMapStringUint     *map[string]uint
	FMapStringUint8       map[string]uint8
	FptrMapStringUint8    *map[string]uint8
	FMapStringUint16      map[string]uint16
	FptrMapStringUint16   *map[string]uint16
	FMapStringUint32      map[string]uint32
	FptrMapStringUint32   *map[string]uint32
	FMapStringUint64      map[string]uint64
	FptrMapStringUint64   *map[string]uint64
	FMapStringUintptr     map[string]uintptr
	FptrMapStringUintptr  *map[string]uintptr
	FMapStringInt         map[string]int
	FptrMapStringInt      *map[string]int
	FMapStringInt8        map[string]int8
	FptrMapStringInt8     *map[string]int8
	FMapStringInt16       map[string]int16
	FptrMapStringInt16    *map[string]int16
	FMapStringInt32       map[string]int32
	FptrMapStringInt32    *map[string]int32
	FMapStringInt64       map[string]int64
	FptrMapStringInt64    *map[string]int64
	FMapStringFloat32     map[string]float32
	FptrMapStringFloat32  *map[string]float32
	FMapStringFloat64     map[string]float64
	FptrMapStringFloat64  *map[string]float64
	FMapStringBool        map[string]bool
	FptrMapStringBool     *map[string]bool
	FMapFloat32Intf       map[float32]interface{}
	FptrMapFloat32Intf    *map[float32]interface{}
	FMapFloat32String     map[float32]string
	FptrMapFloat32String  *map[float32]string
	FMapFloat32Uint       map[float32]uint
	FptrMapFloat32Uint    *map[float32]uint
	FMapFloat32Uint8      map[float32]uint8
	FptrMapFloat32Uint8   *map[float32]uint8
	FMapFloat32Uint16     map[float32]uint16
	FptrMapFloat32Uint16  *map[float32]uint16
	FMapFloat32Uint32     map[float32]uint32
	FptrMapFloat32Uint32  *map[float32]uint32
	FMapFloat32Uint64     map[float32]uint64
	FptrMapFloat32Uint64  *map[float32]uint64
	FMapFloat32Uintptr    map[float32]uintptr
	FptrMapFloat32Uintptr *map[float32]uintptr
	FMapFloat32Int        map[float32]int
	FptrMapFloat32Int     *map[float32]int
	FMapFloat32Int8       map[float32]int8
	FptrMapFloat32Int8    *map[float32]int8
	FMapFloat32Int16      map[float32]int16
	FptrMapFloat32Int16   *map[float32]int16
	FMapFloat32Int32      map[float32]int32
	FptrMapFloat32Int32   *map[float32]int32
	FMapFloat32Int64      map[float32]int64
	FptrMapFloat32Int64   *map[float32]int64
	FMapFloat32Float32    map[float32]float32
	FptrMapFloat32Float32 *map[float32]float32
	FMapFloat32Float64    map[float32]float64
	FptrMapFloat32Float64 *map[float32]float64
	FMapFloat32Bool       map[float32]bool
	FptrMapFloat32Bool    *map[float32]bool
	FMapFloat64Intf       map[float64]interface{}
	FptrMapFloat64Intf    *map[float64]interface{}
	FMapFloat64String     map[float64]string
	FptrMapFloat64String  *map[float64]string
	FMapFloat64Uint       map[float64]uint
	FptrMapFloat64Uint    *map[float64]uint
	FMapFloat64Uint8      map[float64]uint8
	FptrMapFloat64Uint8   *map[float64]uint8
	FMapFloat64Uint16     map[float64]uint16
	FptrMapFloat64Uint16  *map[float64]uint16
	FMapFloat64Uint32     map[float64]uint32
	FptrMapFloat64Uint32  *map[float64]uint32
	FMapFloat64Uint64     map[float64]uint64
	FptrMapFloat64Uint64  *map[float64]uint64
	FMapFloat64Uintptr    map[float64]uintptr
	FptrMapFloat64Uintptr *map[float64]uintptr
	FMapFloat64Int        map[float64]int
	FptrMapFloat64Int     *map[float64]int
	FMapFloat64Int8       map[float64]int8
	FptrMapFloat64Int8    *map[float64]int8
	FMapFloat64Int16      map[float64]int16
	FptrMapFloat64Int16   *map[float64]int16
	FMapFloat64Int32      map[float64]int32
	FptrMapFloat64Int32   *map[float64]int32
	FMapFloat64Int64      map[float64]int64
	FptrMapFloat64Int64   *map[float64]int64
	FMapFloat64Float32    map[float64]float32
	FptrMapFloat64Float32 *map[float64]float32
	FMapFloat64Float64    map[float64]float64
	FptrMapFloat64Float64 *map[float64]float64
	FMapFloat64Bool       map[float64]bool
	FptrMapFloat64Bool    *map[float64]bool
	FMapUintIntf          map[uint]interface{}
	FptrMapUintIntf       *map[uint]interface{}
	FMapUintString        map[uint]string
	FptrMapUintString     *map[uint]string
	FMapUintUint          map[uint]uint
	FptrMapUintUint       *map[uint]uint
	FMapUintUint8         map[uint]uint8
	FptrMapUintUint8      *map[uint]uint8
	FMapUintUint16        map[uint]uint16
	FptrMapUintUint16     *map[uint]uint16
	FMapUintUint32        map[uint]uint32
	FptrMapUintUint32     *map[uint]uint32
	FMapUintUint64        map[uint]uint64
	FptrMapUintUint64     *map[uint]uint64
	FMapUintUintptr       map[uint]uintptr
	FptrMapUintUintptr    *map[uint]uintptr
	FMapUintInt           map[uint]int
	FptrMapUintInt        *map[uint]int
	FMapUintInt8          map[uint]int8
	FptrMapUintInt8       *map[uint]int8
	FMapUintInt16         map[uint]int16
	FptrMapUintInt16      *map[uint]int16
	FMapUintInt32         map[uint]int32
	FptrMapUintInt32      *map[uint]int32
	FMapUintInt64         map[uint]int64
	FptrMapUintInt64      *map[uint]int64
	FMapUintFloat32       map[uint]float32
	FptrMapUintFloat32    *map[uint]float32
	FMapUintFloat64       map[uint]float64
	FptrMapUintFloat64    *map[uint]float64
	FMapUintBool          map[uint]bool
	FptrMapUintBool       *map[uint]bool
	FMapUint8Intf         map[uint8]interface{}
	FptrMapUint8Intf      *map[uint8]interface{}
	FMapUint8String       map[uint8]string
	FptrMapUint8String    *map[uint8]string
	FMapUint8Uint         map[uint8]uint
	FptrMapUint8Uint      *map[uint8]uint
	FMapUint8Uint8        map[uint8]uint8
	FptrMapUint8Uint8     *map[uint8]uint8
	FMapUint8Uint16       map[uint8]uint16
	FptrMapUint8Uint16    *map[uint8]uint16
	FMapUint8Uint32       map[uint8]uint32
	FptrMapUint8Uint32    *map[uint8]uint32
	FMapUint8Uint64       map[uint8]uint64
	FptrMapUint8Uint64    *map[uint8]uint64
	FMapUint8Uintptr      map[uint8]uintptr
	FptrMapUint8Uintptr   *map[uint8]uintptr
	FMapUint8Int          map[uint8]int
	FptrMapUint8Int       *map[uint8]int
	FMapUint8Int8         map[uint8]int8
	FptrMapUint8Int8      *map[uint8]int8
	FMapUint8Int16        map[uint8]int16
	FptrMapUint8Int16     *map[uint8]int16
	FMapUint8Int32        map[uint8]int32
	FptrMapUint8Int32     *map[uint8]int32
	FMapUint8Int64        map[uint8]int64
	FptrMapUint8Int64     *map[uint8]int64
	FMapUint8Float32      map[uint8]float32
	FptrMapUint8Float32   *map[uint8]float32
	FMapUint8Float64      map[uint8]float64
	FptrMapUint8Float64   *map[uint8]float64
	FMapUint8Bool         map[uint8]bool
	FptrMapUint8Bool      *map[uint8]bool
	FMapUint16Intf        map[uint16]interface{}
	FptrMapUint16Intf     *map[uint16]interface{}
	FMapUint16String      map[uint16]string
	FptrMapUint16String   *map[uint16]string
	FMapUint16Uint        map[uint16]uint
	FptrMapUint16Uint     *map[uint16]uint
	FMapUint16Uint8       map[uint16]uint8
	FptrMapUint16Uint8    *map[uint16]uint8
	FMapUint16Uint16      map[uint16]uint16
	FptrMapUint16Uint16   *map[uint16]uint16
	FMapUint16Uint32      map[uint16]uint32
	FptrMapUint16Uint32   *map[uint16]uint32
	FMapUint16Uint64      map[uint16]uint64
	FptrMapUint16Uint64   *map[uint16]uint64
	FMapUint16Uintptr     map[uint16]uintptr
	FptrMapUint16Uintptr  *map[uint16]uintptr
	FMapUint16Int         map[uint16]int
	FptrMapUint16Int      *map[uint16]int
	FMapUint16Int8        map[uint16]int8
	FptrMapUint16Int8     *map[uint16]int8
	FMapUint16Int16       map[uint16]int16
	FptrMapUint16Int16    *map[uint16]int16
	FMapUint16Int32       map[uint16]int32
	FptrMapUint16Int32    *map[uint16]int32
	FMapUint16Int64       map[uint16]int64
	FptrMapUint16Int64    *map[uint16]int64
	FMapUint16Float32     map[uint16]float32
	FptrMapUint16Float32  *map[uint16]float32
	FMapUint16Float64     map[uint16]float64
	FptrMapUint16Float64  *map[uint16]float64
	FMapUint16Bool        map[uint16]bool
	FptrMapUint16Bool     *map[uint16]bool
	FMapUint32Intf        map[uint32]interface{}
	FptrMapUint32Intf     *map[uint32]interface{}
	FMapUint32String      map[uint32]string
	FptrMapUint32String   *map[uint32]string
	FMapUint32Uint        map[uint32]uint
	FptrMapUint32Uint     *map[uint32]uint
	FMapUint32Uint8       map[uint32]uint8
	FptrMapUint32Uint8    *map[uint32]uint8
	FMapUint32Uint16      map[uint32]uint16
	FptrMapUint32Uint16   *map[uint32]uint16
	FMapUint32Uint32      map[uint32]uint32
	FptrMapUint32Uint32   *map[uint32]uint32
	FMapUint32Uint64      map[uint32]uint64
	FptrMapUint32Uint64   *map[uint32]uint64
	FMapUint32Uintptr     map[uint32]uintptr
	FptrMapUint32Uintptr  *map[uint32]uintptr
	FMapUint32Int         map[uint32]int
	FptrMapUint32Int      *map[uint32]int
	FMapUint32Int8        map[uint32]int8
	FptrMapUint32Int8     *map[uint32]int8
	FMapUint32Int16       map[uint32]int16
	FptrMapUint32Int16    *map[uint32]int16
	FMapUint32Int32       map[uint32]int32
	FptrMapUint32Int32    *map[uint32]int32
	FMapUint32Int64       map[uint32]int64
	FptrMapUint32Int64    *map[uint32]int64
	FMapUint32Float32     map[uint32]float32
	FptrMapUint32Float32  *map[uint32]float32
	FMapUint32Float64     map[uint32]float64
	FptrMapUint32Float64  *map[uint32]float64
	FMapUint32Bool        map[uint32]bool
	FptrMapUint32Bool     *map[uint32]bool
	FMapUint64Intf        map[uint64]interface{}
	FptrMapUint64Intf     *map[uint64]interface{}
	FMapUint64String      map[uint64]string
	FptrMapUint64String   *map[uint64]string
	FMapUint64Uint        map[uint64]uint
	FptrMapUint64Uint     *map[uint64]uint
	FMapUint64Uint8       map[uint64]uint8
	FptrMapUint64Uint8    *map[uint64]uint8
	FMapUint64Uint16      map[uint64]uint16
	FptrMapUint64Uint16   *map[uint64]uint16
	FMapUint64Uint32      map[uint64]uint32
	FptrMapUint64Uint32   *map[uint64]uint32
	FMapUint64Uint64      map[uint64]uint64
	FptrMapUint64Uint64   *map[uint64]uint64
	FMapUint64Uintptr     map[uint64]uintptr
	FptrMapUint64Uintptr  *map[uint64]uintptr
	FMapUint64Int         map[uint64]int
	FptrMapUint64Int      *map[uint64]int
	FMapUint64Int8        map[uint64]int8
	FptrMapUint64Int8     *map[uint64]int8
	FMapUint64Int16       map[uint64]int16
	FptrMapUint64Int16    *map[uint64]int16
	FMapUint64Int32       map[uint64]int32
	FptrMapUint64Int32    *map[uint64]int32
	FMapUint64Int64       map[uint64]int64
	FptrMapUint64Int64    *map[uint64]int64
	FMapUint64Float32     map[uint64]float32
	FptrMapUint64Float32  *map[uint64]float32
	FMapUint64Float64     map[uint64]float64
	FptrMapUint64Float64  *map[uint64]float64
	FMapUint64Bool        map[uint64]bool
	FptrMapUint64Bool     *map[uint64]bool
	FMapUintptrIntf       map[uintptr]interface{}
	FptrMapUintptrIntf    *map[uintptr]interface{}
	FMapUintptrString     map[uintptr]string
	FptrMapUintptrString  *map[uintptr]string
	FMapUintptrUint       map[uintptr]uint
	FptrMapUintptrUint    *map[uintptr]uint
	FMapUintptrUint8      map[uintptr]uint8
	FptrMapUintptrUint8   *map[uintptr]uint8
	FMapUintptrUint16     map[uintptr]uint16
	FptrMapUintptrUint16  *map[uintptr]uint16
	FMapUintptrUint32     map[uintptr]uint32
	FptrMapUintptrUint32  *map[uintptr]uint32
	FMapUintptrUint64     map[uintptr]uint64
	FptrMapUintptrUint64  *map[uintptr]uint64
	FMapUintptrUintptr    map[uintptr]uintptr
	FptrMapUintptrUintptr *map[uintptr]uintptr
	FMapUintptrInt        map[uintptr]int
	FptrMapUintptrInt     *map[uintptr]int
	FMapUintptrInt8       map[uintptr]int8
	FptrMapUintptrInt8    *map[uintptr]int8
	FMapUintptrInt16      map[uintptr]int16
	FptrMapUintptrInt16   *map[uintptr]int16
	FMapUintptrInt32      map[uintptr]int32
	FptrMapUintptrInt32   *map[uintptr]int32
	FMapUintptrInt64      map[uintptr]int64
	FptrMapUintptrInt64   *map[uintptr]int64
	FMapUintptrFloat32    map[uintptr]float32
	FptrMapUintptrFloat32 *map[uintptr]float32
	FMapUintptrFloat64    map[uintptr]float64
	FptrMapUintptrFloat64 *map[uintptr]float64
	FMapUintptrBool       map[uintptr]bool
	FptrMapUintptrBool    *map[uintptr]bool
	FMapIntIntf           map[int]interface{}
	FptrMapIntIntf        *map[int]interface{}
	FMapIntString         map[int]string
	FptrMapIntString      *map[int]string
	FMapIntUint           map[int]uint
	FptrMapIntUint        *map[int]uint
	FMapIntUint8          map[int]uint8
	FptrMapIntUint8       *map[int]uint8
	FMapIntUint16         map[int]uint16
	FptrMapIntUint16      *map[int]uint16
	FMapIntUint32         map[int]uint32
	FptrMapIntUint32      *map[int]uint32
	FMapIntUint64         map[int]uint64
	FptrMapIntUint64      *map[int]uint64
	FMapIntUintptr        map[int]uintptr
	FptrMapIntUintptr     *map[int]uintptr
	FMapIntInt            map[int]int
	FptrMapIntInt         *map[int]int
	FMapIntInt8           map[int]int8
	FptrMapIntInt8        *map[int]int8
	FMapIntInt16          map[int]int16
	FptrMapIntInt16       *map[int]int16
	FMapIntInt32          map[int]int32
	FptrMapIntInt32       *map[int]int32
	FMapIntInt64          map[int]int64
	FptrMapIntInt64       *map[int]int64
	FMapIntFloat32        map[int]float32
	FptrMapIntFloat32     *map[int]float32
	FMapIntFloat64        map[int]float64
	FptrMapIntFloat64     *map[int]float64
	FMapIntBool           map[int]bool
	FptrMapIntBool        *map[int]bool
	FMapInt8Intf          map[int8]interface{}
	FptrMapInt8Intf       *map[int8]interface{}
	FMapInt8String        map[int8]string
	FptrMapInt8String     *map[int8]string
	FMapInt8Uint          map[int8]uint
	FptrMapInt8Uint       *map[int8]uint
	FMapInt8Uint8         map[int8]uint8
	FptrMapInt8Uint8      *map[int8]uint8
	FMapInt8Uint16        map[int8]uint16
	FptrMapInt8Uint16     *map[int8]uint16
	FMapInt8Uint32        map[int8]uint32
	FptrMapInt8Uint32     *map[int8]uint32
	FMapInt8Uint64        map[int8]uint64
	FptrMapInt8Uint64     *map[int8]uint64
	FMapInt8Uintptr       map[int8]uintptr
	FptrMapInt8Uintptr    *map[int8]uintptr
	FMapInt8Int           map[int8]int
	FptrMapInt8Int        *map[int8]int
	FMapInt8Int8          map[int8]int8
	FptrMapInt8Int8       *map[int8]int8
	FMapInt8Int16         map[int8]int16
	FptrMapInt8Int16      *map[int8]int16
	FMapInt8Int32         map[int8]int32
	FptrMapInt8Int32      *map[int8]int32
	FMapInt8Int64         map[int8]int64
	FptrMapInt8Int64      *map[int8]int64
	FMapInt8Float32       map[int8]float32
	FptrMapInt8Float32    *map[int8]float32
	FMapInt8Float64       map[int8]float64
	FptrMapInt8Float64    *map[int8]float64
	FMapInt8Bool          map[int8]bool
	FptrMapInt8Bool       *map[int8]bool
	FMapInt16Intf         map[int16]interface{}
	FptrMapInt16Intf      *map[int16]interface{}
	FMapInt16String       map[int16]string
	FptrMapInt16String    *map[int16]string
	FMapInt16Uint         map[int16]uint
	FptrMapInt16Uint      *map[int16]uint
	FMapInt16Uint8        map[int16]uint8
	FptrMapInt16Uint8     *map[int16]uint8
	FMapInt16Uint16       map[int16]uint16
	FptrMapInt16Uint16    *map[int16]uint16
	FMapInt16Uint32       map[int16]uint32
	FptrMapInt16Uint32    *map[int16]uint32
	FMapInt16Uint64       map[int16]uint64
	FptrMapInt16Uint64    *map[int16]uint64
	FMapInt16Uintptr      map[int16]uintptr
	FptrMapInt16Uintptr   *map[int16]uintptr
	FMapInt16Int          map[int16]int
	FptrMapInt16Int       *map[int16]int
	FMapInt16Int8         map[int16]int8
	FptrMapInt16Int8      *map[int16]int8
	FMapInt16Int16        map[int16]int16
	FptrMapInt16Int16     *map[int16]int16
	FMapInt16Int32        map[int16]int32
	FptrMapInt16Int32     *map[int16]int32
	FMapInt16Int64        map[int16]int64
	FptrMapInt16Int64     *map[int16]int64
	FMapInt16Float32      map[int16]float32
	FptrMapInt16Float32   *map[int16]float32
	FMapInt16Float64      map[int16]float64
	FptrMapInt16Float64   *map[int16]float64
	FMapInt16Bool         map[int16]bool
	FptrMapInt16Bool      *map[int16]bool
	FMapInt32Intf         map[int32]interface{}
	FptrMapInt32Intf      *map[int32]interface{}
	FMapInt32String       map[int32]string
	FptrMapInt32String    *map[int32]string
	FMapInt32Uint         map[int32]uint
	FptrMapInt32Uint      *map[int32]uint
	FMapInt32Uint8        map[int32]uint8
	FptrMapInt32Uint8     *map[int32]uint8
	FMapInt32Uint16       map[int32]uint16
	FptrMapInt32Uint16    *map[int32]uint16
	FMapInt32Uint32       map[int32]uint32
	FptrMapInt32Uint32    *map[int32]uint32
	FMapInt32Uint64       map[int32]uint64
	FptrMapInt32Uint64    *map[int32]uint64
	FMapInt32Uintptr      map[int32]uintptr
	FptrMapInt32Uintptr   *map[int32]uintptr
	FMapInt32Int          map[int32]int
	FptrMapInt32Int       *map[int32]int
	FMapInt32Int8         map[int32]int8
	FptrMapInt32Int8      *map[int32]int8
	FMapInt32Int16        map[int32]int16
	FptrMapInt32Int16     *map[int32]int16
	FMapInt32Int32        map[int32]int32
	FptrMapInt32Int32     *map[int32]int32
	FMapInt32Int64        map[int32]int64
	FptrMapInt32Int64     *map[int32]int64
	FMapInt32Float32      map[int32]float32
	FptrMapInt32Float32   *map[int32]float32
	FMapInt32Float64      map[int32]float64
	FptrMapInt32Float64   *map[int32]float64
	FMapInt32Bool         map[int32]bool
	FptrMapInt32Bool      *map[int32]bool
	FMapInt64Intf         map[int64]interface{}
	FptrMapInt64Intf      *map[int64]interface{}
	FMapInt64String       map[int64]string
	FptrMapInt64String    *map[int64]string
	FMapInt64Uint         map[int64]uint
	FptrMapInt64Uint      *map[int64]uint
	FMapInt64Uint8        map[int64]uint8
	FptrMapInt64Uint8     *map[int64]uint8
	FMapInt64Uint16       map[int64]uint16
	FptrMapInt64Uint16    *map[int64]uint16
	FMapInt64Uint32       map[int64]uint32
	FptrMapInt64Uint32    *map[int64]uint32
	FMapInt64Uint64       map[int64]uint64
	FptrMapInt64Uint64    *map[int64]uint64
	FMapInt64Uintptr      map[int64]uintptr
	FptrMapInt64Uintptr   *map[int64]uintptr
	FMapInt64Int          map[int64]int
	FptrMapInt64Int       *map[int64]int
	FMapInt64Int8         map[int64]int8
	FptrMapInt64Int8      *map[int64]int8
	FMapInt64Int16        map[int64]int16
	FptrMapInt64Int16     *map[int64]int16
	FMapInt64Int32        map[int64]int32
	FptrMapInt64Int32     *map[int64]int32
	FMapInt64Int64        map[int64]int64
	FptrMapInt64Int64     *map[int64]int64
	FMapInt64Float32      map[int64]float32
	FptrMapInt64Float32   *map[int64]float32
	FMapInt64Float64      map[int64]float64
	FptrMapInt64Float64   *map[int64]float64
	FMapInt64Bool         map[int64]bool
	FptrMapInt64Bool      *map[int64]bool
	FMapBoolIntf          map[bool]interface{}
	FptrMapBoolIntf       *map[bool]interface{}
	FMapBoolString        map[bool]string
	FptrMapBoolString     *map[bool]string
	FMapBoolUint          map[bool]uint
	FptrMapBoolUint       *map[bool]uint
	FMapBoolUint8         map[bool]uint8
	FptrMapBoolUint8      *map[bool]uint8
	FMapBoolUint16        map[bool]uint16
	FptrMapBoolUint16     *map[bool]uint16
	FMapBoolUint32        map[bool]uint32
	FptrMapBoolUint32     *map[bool]uint32
	FMapBoolUint64        map[bool]uint64
	FptrMapBoolUint64     *map[bool]uint64
	FMapBoolUintptr       map[bool]uintptr
	FptrMapBoolUintptr    *map[bool]uintptr
	FMapBoolInt           map[bool]int
	FptrMapBoolInt        *map[bool]int
	FMapBoolInt8          map[bool]int8
	FptrMapBoolInt8       *map[bool]int8
	FMapBoolInt16         map[bool]int16
	FptrMapBoolInt16      *map[bool]int16
	FMapBoolInt32         map[bool]int32
	FptrMapBoolInt32      *map[bool]int32
	FMapBoolInt64         map[bool]int64
	FptrMapBoolInt64      *map[bool]int64
	FMapBoolFloat32       map[bool]float32
	FptrMapBoolFloat32    *map[bool]float32
	FMapBoolFloat64       map[bool]float64
	FptrMapBoolFloat64    *map[bool]float64
	FMapBoolBool          map[bool]bool
	FptrMapBoolBool       *map[bool]bool
}

// -----------

type testMammoth2Binary uint64

func (x testMammoth2Binary) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	bigen.PutUint64(data, uint64(x))
	return
}
func (x *testMammoth2Binary) UnmarshalBinary(data []byte) (err error) {
	*x = testMammoth2Binary(bigen.Uint64(data))
	return
}

type testMammoth2Text uint64

func (x testMammoth2Text) MarshalText() (data []byte, err error) {
	data = []byte(fmt.Sprintf("%b", uint64(x)))
	return
}
func (x *testMammoth2Text) UnmarshalText(data []byte) (err error) {
	_, err = fmt.Sscanf(string(data), "%b", (*uint64)(x))
	return
}

type testMammoth2Json uint64

func (x testMammoth2Json) MarshalJSON() (data []byte, err error) {
	data = []byte(fmt.Sprintf("%v", uint64(x)))
	return
}
func (x *testMammoth2Json) UnmarshalJSON(data []byte) (err error) {
	_, err = fmt.Sscanf(string(data), "%v", (*uint64)(x))
	return
}

type testMammoth2Basic [4]uint64

type TestMammoth2Wrapper struct {
	V TestMammoth2
	T testMammoth2Text
	B testMammoth2Binary
	J testMammoth2Json
	C testMammoth2Basic
	M map[testMammoth2Basic]TestMammoth2
	L []TestMammoth2
	A [4]int64
}
