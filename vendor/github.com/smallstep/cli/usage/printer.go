package usage

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"text/template"

	md "github.com/smallstep/cli/pkg/blackfriday"
	"github.com/urfave/cli"
)

var sectionRe = regexp.MustCompile(`(?m:^##)`)

//var sectionRe = regexp.MustCompile(`^## [^\n]*$`)

// HelpPrinter overwrites cli.HelpPrinter and prints the formatted help to the terminal.
func HelpPrinter(w io.Writer, templ string, data interface{}) {
	b := helpPreprocessor(w, templ, data)
	w.Write(Render(b))
}

func htmlHelpPrinter(w io.Writer, templ string, data interface{}) []byte {
	b := helpPreprocessor(w, templ, data)
	w.Write([]byte(`<html><head><title>step command line documentation</title>`))
	w.Write([]byte(`<link href="/style.css" rel="stylesheet" type="text/css">`))
	w.Write([]byte(`</head><body><div class="wrapper markdown-body command">`))
	html := md.Run(b)
	w.Write(html)
	w.Write([]byte(`</div></body></html>`))

	return html
}

func markdownHelpPrinter(w io.Writer, templ string, data interface{}) {
	b := helpPreprocessor(w, templ, data)
	var frontMatterTemplate = `---
layout: auto-doc
title: {{.HelpName}}
---

`
	t, err := template.New("frontmatter").Parse(frontMatterTemplate)
	if err != nil {
		panic(err)
	}
	err = t.Execute(w, data)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func helpPreprocessor(w io.Writer, templ string, data interface{}) []byte {
	buf := new(bytes.Buffer)
	cli.HelpPrinterCustom(buf, templ, data, nil)
	//w.Write(buf.Bytes())
	s := string(markdownify(buf.Bytes()))
	// Move the OPTIONS section to the right place. urfave puts them at the end
	// of the file, we want them to be after POSITIONAL ARGUMENTS, DESCRIPTION,
	// USAGE, or NAME (in that order, depending on which sections exist).
	optLoc := strings.Index(s, "## OPTIONS")
	if optLoc != -1 {
		optEnd := findSectionEnd("OPTIONS", s)
		if optEnd != -1 {
			options := s[optLoc:optEnd]
			s = s[:optLoc] + s[optEnd:]
			if newLoc := findSectionEnd("POSITIONAL ARGUMENTS", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("DESCRIPTION", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("USAGE", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("NAME", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else {
				// Keep it at the end I guess :/.
				s = s + options
			}
		}
	}

	return []byte(s)
}

func findSectionEnd(h, s string) int {
	start := strings.Index(s, fmt.Sprintf("## %s", h))
	if start == -1 {
		return start
	}
	nextSection := sectionRe.FindStringIndex(s[start+2:])
	if nextSection == nil {
		return len(s)
	}
	return start + 2 + nextSection[0]
}

// Convert some stuff that we can't easily write in help files because
//  backticks and raw strings don't mix:
// - "<foo>" to "`foo`"
// - "'''" to "```"
func markdownify(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '<':
			if b[i-1] != '\\' {
				b[i] = '`'
			} else {
				copy(b[i-1:], b[i:])
			}
		case '>':
			if b[i-1] != '\\' {
				b[i] = '`'
			} else {
				copy(b[i-1:], b[i:])
			}
		case '\'':
			if len(b) >= i+3 && string(b[i:i+3]) == "'''" {
				b[i] = '`'
				b[i+1] = '`'
				b[i+2] = '`'
				i += 2
			}
		}
	}
	return b
}
