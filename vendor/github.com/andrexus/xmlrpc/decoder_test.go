package xmlrpc

import (
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

type book struct {
	Title  string
	Amount int
}

type bookUnexported struct {
	title  string
	amount int
}

var unmarshalTests = []struct {
	value interface{}
	ptr   interface{}
	xml   string
}{
	{100, new(*int), "<value><int>100</int></value>"},
	{int64(45659074), new(*int64), "<value><i8>45659074</i8></value>"},
	{"Once upon a time", new(*string), "<value><string>Once upon a time</string></value>"},
	{"Mike & Mick <London, UK>", new(*string), "<value><string>Mike &amp; Mick &lt;London, UK&gt;</string></value>"},
	{"Once upon a time", new(*string), "<value>Once upon a time</value>"},
	{"T25jZSB1cG9uIGEgdGltZQ==", new(*string), "<value><base64>T25jZSB1cG9uIGEgdGltZQ==</base64></value>"},
	{true, new(*bool), "<value><boolean>1</boolean></value>"},
	{false, new(*bool), "<value><boolean>0</boolean></value>"},
	{12.134, new(*float32), "<value><double>12.134</double></value>"},
	{-12.134, new(*float32), "<value><double>-12.134</double></value>"},
	{time.Unix(1386622812, 0).UTC(), new(*time.Time), "<value><dateTime.iso8601>20131209T21:00:12</dateTime.iso8601></value>"},
	{[]int{1, 5, 7}, new(*[]int), "<value><array><data><value><int>1</int></value><value><int>5</int></value><value><int>7</int></value></data></array></value>"},
	{book{"War and Piece", 20}, new(*book), "<value><struct><member><name>Title</name><value><string>War and Piece</string></value></member><member><name>Amount</name><value><int>20</int></value></member></struct></value>"},
	{bookUnexported{}, new(*bookUnexported), "<value><struct><member><name>title</name><value><string>War and Piece</string></value></member><member><name>amount</name><value><int>20</int></value></member></struct></value>"},
	{0, new(*int), "<value><int></int></value>"},
	{[]interface{}{"A", "5"}, new(interface{}), "<value><array><data><value><string>A</string></value><value><string>5</string></value></data></array></value>"},
	//{map[string]interface{}{"Name": "John Smith",
	//	"Age":   6,
	//	"Wight": []interface{}{66.67, 100.5}},
	//	new(interface{}), "<value><struct><member><name>Name</name><value><string>John Smith</string></value></member><member><name>Age</name><value><int>6</int></value></member><member><name>Wight</name><value><array><data><value><double>66.67</double></value><value><double>100.5</double></value></data></array></value></member></struct></value>"},
	{map[string]interface{}{"Name": "John Smith"}, new(interface{}), "<value><struct><member><name>Name</name><value><string>John Smith</string></value></member></struct></value>"},
}

func Test_unmarshal(t *testing.T) {
	for _, tt := range unmarshalTests {
		v := reflect.New(reflect.TypeOf(tt.value))
		if err := unmarshal([]byte(tt.xml), v.Interface()); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		v = v.Elem()

		if v.Kind() == reflect.Slice {
			vv := reflect.ValueOf(tt.value)
			if vv.Len() != v.Len() {
				t.Fatalf("unmarshal error:\nexpected: %v\n     got: %v", tt.value, v.Interface())
			}
			for i := 0; i < v.Len(); i++ {
				if v.Index(i).Interface() != vv.Index(i).Interface() {
					t.Fatalf("unmarshal error:\nexpected: %v\n     got: %v", tt.value, v.Interface())
				}
			}
		} else {
			a1 := v.Interface()
			a2 := interface{}(tt.value)

			if !reflect.DeepEqual(a1, a2) {
				t.Fatalf("unmarshal error:\nexpected: %v\n     got: %v", tt.value, v.Interface())
			}
		}
	}
}

func Test_unmarshalToNil(t *testing.T) {
	for _, tt := range unmarshalTests {
		if err := unmarshal([]byte(tt.xml), tt.ptr); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
	}
}

func Test_typeMismatchError(t *testing.T) {
	var s string

	tt := unmarshalTests[0]
	var err error

	if err = unmarshal([]byte(tt.xml), &s); err == nil {
		t.Fatal("unmarshal error: expected error, but didn't get it")
	}

	if _, ok := err.(TypeMismatchError); !ok {
		t.Fatal("unmarshal error: expected type mistmatch error, but didn't get it")
	}
}

func Test_unmarshalEmptyValueTag(t *testing.T) {
	var v int

	if err := unmarshal([]byte("<value/>"), &v); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
}

func Test_decodeNonUTF8Response(t *testing.T) {
	data, err := ioutil.ReadFile("fixtures/cp1251.xml")
	if err != nil {
		t.Fatal(err)
	}

	CharsetReader = decode

	var s string
	if err = unmarshal(data, &s); err != nil {
		fmt.Println(err)
		t.Fatal("unmarshal error: cannot decode non utf-8 response")
	}

	expected := "Л.Н. Толстой - Война и Мир"

	if s != expected {
		t.Fatalf("unmarshal error:\nexpected: %v\n     got: %v", expected, s)
	}

	CharsetReader = nil
}

func decode(charset string, input io.Reader) (io.Reader, error) {
	if charset != "cp1251" {
		return nil, fmt.Errorf("unsupported charset")
	}

	return transform.NewReader(input, charmap.Windows1251.NewDecoder()), nil
}
