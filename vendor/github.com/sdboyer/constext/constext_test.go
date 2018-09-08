package constext

import (
	"context"
	"runtime"
	"testing"
	"time"
)

var bgc = context.Background()

func TestConsCancel(t *testing.T) {
	c1, cancel1 := context.WithCancel(bgc)
	c2, cancel2 := context.WithCancel(bgc)

	cc, _ := Cons(c1, c2)
	if _, has := cc.Deadline(); has {
		t.Fatal("constext should not have a deadline if parents do not")
	}

	cancel1()
	select {
	case <-cc.Done():
	case <-time.After(1 * time.Second):
		buf := make([]byte, 10<<10)
		n := runtime.Stack(buf, true)
		t.Fatalf("timed out waiting for parent to quit; stacks:\n%s", buf[:n])
	}

	cc, _ = Cons(c1, c2)
	if cc.Err() == nil {
		t.Fatal("pre-canceled car constext did not begin canceled")
	}

	cc, _ = Cons(c2, c1)
	if cc.Err() == nil {
		t.Fatal("pre-canceled cdr constext did not begin canceled")
	}

	c3, _ := context.WithCancel(bgc)
	cc, _ = Cons(c3, c2)
	cancel2()
	select {
	case <-cc.Done():
	case <-time.After(1 * time.Second):
		buf := make([]byte, 10<<10)
		n := runtime.Stack(buf, true)
		t.Fatalf("timed out waiting for cdr to quit; stacks:\n%s", buf[:n])
	}
}

func TestCancelPassdown(t *testing.T) {
	c1, cancel1 := context.WithCancel(bgc)
	c2, _ := context.WithCancel(bgc)
	cc, _ := Cons(c1, c2)
	c3, _ := context.WithCancel(cc)

	cancel1()
	select {
	case <-c3.Done():
	case <-time.After(1 * time.Second):
		buf := make([]byte, 10<<10)
		n := runtime.Stack(buf, true)
		t.Fatalf("timed out waiting for parent to quit; stacks:\n%s", buf[:n])
	}

	c1, cancel1 = context.WithCancel(bgc)
	cc, _ = Cons(c1, c2)
	c3 = context.WithValue(cc, "foo", "bar")

	cancel1()
	select {
	case <-c3.Done():
	case <-time.After(1 * time.Second):
		buf := make([]byte, 10<<10)
		n := runtime.Stack(buf, true)
		t.Fatalf("timed out waiting for parent to quit; stacks:\n%s", buf[:n])
	}
}

func TestValueUnion(t *testing.T) {
	c1 := context.WithValue(bgc, "foo", "bar")
	c2 := context.WithValue(bgc, "foo", "baz")
	cc, _ := Cons(c1, c2)

	v := cc.Value("foo")
	if v != "bar" {
		t.Fatalf("wanted value of \"foo\" from car, \"bar\", got %q", v)
	}

	c3 := context.WithValue(bgc, "bar", "quux")
	cc2, _ := Cons(c1, c3)
	v = cc2.Value("bar")
	if v != "quux" {
		t.Fatalf("wanted value from cdr, \"quux\", got %q", v)
	}

	cc, _ = Cons(cc, c3)
	v = cc.Value("bar")
	if v != "quux" {
		t.Fatalf("wanted value from nested cdr, \"quux\", got %q", v)
	}
}

func TestDeadline(t *testing.T) {
	t1 := time.Now().Add(1 * time.Second)
	c1, _ := context.WithDeadline(bgc, t1)
	cc, _ := Cons(c1, bgc)

	cct, ok := cc.Deadline()
	if !ok {
		t.Fatal("constext claimed to not have any deadline, but car did")
	}
	if cct != t1 {
		t.Fatal("constext did not have correct deadline")
	}

	cc, _ = Cons(bgc, c1)
	cct, ok = cc.Deadline()
	if !ok {
		t.Fatal("constext claimed to not have any deadline, but cdr did")
	}
	if cct != t1 {
		t.Fatal("constext did not have correct deadline")
	}

	t2 := time.Now().Add(1 * time.Second)
	c2, _ := context.WithDeadline(bgc, t2)
	cc, _ = Cons(c1, c2)
	cct, ok = cc.Deadline()
	if !ok {
		t.Fatal("constext claimed to not have any deadline, but both parents did")
	}

	if cct != t1 {
		t.Fatal("got wrong deadline time back")
	}

	cc, _ = Cons(c2, c1)
	cct, ok = cc.Deadline()
	if !ok {
		t.Fatal("constext claimed to not have any deadline, but both parents did")
	}

	if cct != t1 {
		t.Fatal("got wrong deadline time back")
	}

	select {
	case <-cc.Done():
	case <-time.After(t1.Sub(time.Now()) + 5*time.Millisecond):
		buf := make([]byte, 10<<10)
		n := runtime.Stack(buf, true)
		t.Fatalf("car did not quit after deadline; stacks:\n%s", buf[:n])
	}
}
