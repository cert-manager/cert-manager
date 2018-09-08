package nuts

import (
	"fmt"
)

func ExampleKey_UUID() {
	type uuid struct{ a, b uint64 }

	u := uuid{
		a: 0xaaaaaaaaaaaaaaaa,
		b: 0xbbbbbbbbbbbbbbbb,
	}

	key := make(Key, 16)
	key[:8].Put(u.a)
	key[8:].Put(u.b)
	fmt.Printf("%#x", key)

	// Output:
	// 0xaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb
}
