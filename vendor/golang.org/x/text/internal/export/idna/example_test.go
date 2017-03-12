// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package idna_test

import (
	"fmt"

	"golang.org/x/text/internal/export/idna"
)

func ExampleNew() {
	var p *idna.Profile

	// Raw Punycode has no restrictions and does no mappings.
	p = idna.New()
	fmt.Println(p.ToASCII("*.faß.com"))

	// Do mappings. Note that star is not allowed in a DNS lookup.
	p = idna.New(
		idna.MapForLookup(),
		idna.Transitional(true)) // Map ß -> ss
	fmt.Println(p.ToASCII("*.faß.com"))

	// Set up a profile maps for lookup, but allows wild cards.
	p = idna.New(
		idna.MapForLookup(),
		idna.Transitional(true),  // Map ß -> ss
		idna.UseSTD3Rules(false)) // Set more permissive ASCII rules.
	fmt.Println(p.ToASCII("*.faß.com"))

	// Output:
	// *.xn--fa-hia.com <nil>
	// *.fass.com idna: disallowed rune U+002E
	// *.fass.com <nil>
}
