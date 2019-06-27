package usage

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/samfoo/ansi"
	md "github.com/smallstep/cli/pkg/blackfriday"
)

// Render renders the given data with a custom markdown renderer.
func Render(b []byte) []byte {
	return md.Run(b, md.WithRenderer(&Renderer{6, 0, nil, nil, false}))
}

var colorEscapeRe = regexp.MustCompile(`\033\[\d*(;\d*)?m?\]?`)
var maxLineLength = 80

func stripColors(b []byte) []byte {
	return colorEscapeRe.ReplaceAll(b, []byte(""))
}

type item struct {
	flags       md.ListType
	term        []byte
	definitions [][]byte
}

type list struct {
	items  []item
	flags  md.ListType
	parent *list
}

func (l *list) isUnordered() bool {
	return !l.isOrdered() && !l.isDefinition()
}

func (l *list) isOrdered() bool {
	return l.flags&md.ListTypeOrdered != 0
}

func (l *list) isDefinition() bool {
	return l.flags&md.ListTypeDefinition != 0
}

func (l *list) containsBlock() bool {
	// TODO: Not sure if we have to check every item or if it gets
	// automatically set on the list?
	return l.flags&md.ListItemContainsBlock != 0
}

type bufqueue struct {
	w    io.Writer
	buf  *bytes.Buffer
	next *bufqueue
	mode RenderMode
}

// RenderMode enumerates different line breaks modes.
type RenderMode int

const (
	// RenderModeKeepBreaks will keep the line breaks in the docs.
	RenderModeKeepBreaks RenderMode = iota
	// RenderModeBreakLines will automatically wrap the lines.
	RenderModeBreakLines
)

// Renderer implements a custom markdown renderer for blackfriday.
type Renderer struct {
	depth     int
	listdepth int
	list      *list
	out       *bufqueue
	inpara    bool
}

func (r *Renderer) write(b []byte) {
	r.out.w.Write(b)
}

func (r *Renderer) printf(s string, a ...interface{}) {
	fmt.Fprintf(r.out.w, s, a...)
}

func (r *Renderer) capture(mode RenderMode) {
	buf := new(bytes.Buffer)
	r.out = &bufqueue{buf, buf, r.out, mode}
}

func (r *Renderer) finishCapture() *bytes.Buffer {
	buf := r.out.buf
	r.out = r.out.next
	return buf
}

func (r *Renderer) inParagraph() bool {
	return r.inpara
}

func (r *Renderer) inList() bool {
	return r.list != nil
}

func (r *Renderer) renderParagraphKeepBreaks(buf *bytes.Buffer) {
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		r.printf(strings.Repeat(" ", r.depth)+"%s\n", scanner.Text())
	}
}

func (r *Renderer) renderParagraphBreakLines(buf *bytes.Buffer, maxlen int) {
	maxlen = maxlen - r.depth
	scanner := bufio.NewScanner(buf)
	scanner.Split(bufio.ScanWords)
	line := []string{}
	length := 0
	for scanner.Scan() {
		word := scanner.Text()
		wordLength := len(stripColors([]byte(word)))
		// Print the line if we've got a collection of words over 80 characters, or if
		// we have a single word that is over 80 characters on an otherwise empty line.
		if length+wordLength > maxlen {
			r.printf(strings.Repeat(" ", r.depth)+"%s\n", strings.Join(line, " "))
			line = []string{word}
			length = wordLength
		} else if length == 0 && wordLength > maxlen {
			r.printf(strings.Repeat(" ", r.depth)+"%s\n", word)
		} else {
			line = append(line, word)
			length += wordLength + 1 // Plus one for space
		}
	}
	if len(line) > 0 {
		r.printf(strings.Repeat(" ", r.depth)+"%s\n", strings.Join(line, " "))
	}
}

func (r *Renderer) renderParagraph(buf *bytes.Buffer) {
	switch r.out.mode {
	case RenderModeKeepBreaks:
		r.renderParagraphKeepBreaks(buf)
	case RenderModeBreakLines:
		r.renderParagraphBreakLines(buf, maxLineLength)
	}
}

// RenderNode implements blackfriday.Renderer interface.
func (r *Renderer) RenderNode(w io.Writer, node *md.Node, entering bool) md.WalkStatus {
	if r.out == nil {
		r.out = &bufqueue{w, nil, nil, RenderModeBreakLines}
	}

	switch node.Type {
	case md.Paragraph:
		// Alternative idea here: call r.RenderNode() with our new buffer as
		// `w`. In the `else` condition here render to the outter buffer and
		// always return md.Terminate. So when we enter a paragraph we start
		// parsing with a new output buffer and capture the output.
		if entering {
			if r.inParagraph() {
				panic("already in paragraph")
			}
			r.inpara = true
			//r.printf(out, "[paragraph:")
			r.capture(r.out.mode)
		} else {
			r.renderParagraph(r.finishCapture())
			// Write a newline unless the parent node is a definition list term.
			if node.Parent.Type != md.Item || node.Parent.ListFlags&md.ListTypeTerm == 0 {
				r.printf("\n")
			}
			r.inpara = false
			//r.printf(w, ":paragraph]")
		}
	case md.Text:
		// TODO: is this necessary? I think all text is in a paragraph.
		if r.inParagraph() {
			r.write(node.Literal)
		} else {
			s := strings.Replace(string(node.Literal), "\n", "\n"+strings.Repeat(" ", r.depth), -1)
			r.printf(s)
		}
	case md.Heading:
		if entering {
			r.printf(ansi.ColorCode("default+bh"))
		} else {
			r.printf(ansi.Reset)
			r.printf("\n")
		}
	case md.Link:
		if entering {
			r.printf(ansi.ColorCode("default+b"))
			//r.printf("\033[2m") // Dim
		} else {
			r.printf(ansi.Reset)
		}
	case md.Strong:
		if entering {
			r.printf(ansi.ColorCode("default+bh"))
		} else {
			r.printf(ansi.Reset)
		}
	case md.Emph:
		if entering {
			r.printf(ansi.ColorCode("default+u"))
		} else {
			r.printf(ansi.Reset)
		}
	case md.Code:
		r.printf(ansi.ColorCode("default+u"))
		r.write(node.Literal)
		r.printf(ansi.Reset)
	case md.List:
		if entering {
			r.listdepth++
			r.list = &list{[]item{}, node.ListFlags, r.list}
			//r.printf("[list (type %s:", node.ListData.ListFlags)
		} else {
			if r.listdepth > 1 && r.list.isDefinition() {
				w := new(tabwriter.Writer)
				w.Init(r.out.w, 0, 8, 4, ' ', tabwriter.StripEscape)
				for _, item := range r.list.items {
					fmt.Fprintf(w, strings.TrimRight(string(item.term), " \n"))
					fmt.Fprintf(w, "\n")
					for _, def := range item.definitions {
						fmt.Fprintf(w, strings.TrimRight(string(def), " \n"))
					}
					fmt.Fprintf(w, "\n\n")
				}
				w.Flush()
			} else {
				ordered := (node.ListFlags&md.ListTypeOrdered != 0)
				unordered := (node.ListFlags&md.ListTypeOrdered == 0 && node.ListFlags&md.ListTypeDefinition == 0)
				for i, item := range r.list.items {
					if ordered || unordered {
						p := bytes.IndexFunc(item.term, func(r rune) bool { return !unicode.IsSpace(r) })
						switch {
						case ordered: // add numbers on ordered lists
							item.term = append(item.term[:p], append([]byte(fmt.Sprintf("%d. ", i+1)), item.term[p:]...)...)
						case unordered: // add bullet points on unordered lists
							item.term = append(item.term[:p], append([]byte("• "), item.term[p:]...)...)
						}
					}

					r.write(item.term)
					for _, def := range item.definitions {
						r.write(def)
					}
				}
			}
			r.listdepth--
			r.list = r.list.parent
			//r.printf(":list]")
		}
	case md.Item:
		incdepth := 4
		//ltype := "normal"
		if node.ListFlags&md.ListTypeTerm != 0 {
			// Nested definition list terms get indented two spaces. Non-nested
			// definition list terms are not indented.
			if r.listdepth > 1 {
				incdepth = 2
			} else {
				incdepth = 0
			}
			//ltype = "dt"
		} else if node.ListFlags&md.ListTypeDefinition != 0 {
			incdepth = 4
			//ltype = "dd"
		}

		if entering {
			//fmt.Fprintf(out, "[list item %s:", ltype)
			r.depth += incdepth
			if r.listdepth > 1 && r.list.isDefinition() {
				r.capture(RenderModeKeepBreaks)
			} else {
				r.capture(RenderModeBreakLines)
			}
			if !r.list.isDefinition() || node.ListFlags&md.ListTypeTerm != 0 {
				r.list.items = append(r.list.items, item{node.ListFlags, nil, nil})
			}
		} else {
			//fmt.Fprintf(out, ":list item]")
			r.depth -= incdepth
			buf := r.finishCapture()
			if r.list.isDefinition() && node.ListFlags&md.ListTypeTerm == 0 {
				i := len(r.list.items) - 1
				r.list.items[i].definitions = append(r.list.items[i].definitions, buf.Bytes())
			} else {
				r.list.items[len(r.list.items)-1].term = buf.Bytes()
			}
		}
	case md.Table:
		if entering {
			r.capture(RenderModeKeepBreaks)
			w := new(tabwriter.Writer)
			w.Init(r.out.w, 1, 8, 2, ' ', tabwriter.StripEscape)
			r.out.w = w
		} else {
			r.out.w.(*tabwriter.Writer).Flush()
			buf := r.finishCapture()
			r.renderParagraphKeepBreaks(buf)
			r.printf("\n")
		}
	case md.TableBody:
		// Do nothing.
	case md.TableHead:
		if entering {
			r.capture(r.out.mode)
		} else {
			// Markdown doens't have a way to create a table without headers.
			// We've opted to fix that here by not rendering headers at all if
			// they're empty.
			result := r.finishCapture().Bytes()
			if strings.TrimSpace(string(stripColors(result))) != "" {
				parts := strings.Split(strings.TrimRight(string(result), "\t\n"), "\t")
				for i := 0; i < len(parts); i++ {
					parts[i] = "\xff" + ansi.ColorCode("default+bh") + "\xff" + parts[i] + "\xff" + ansi.Reset + "\xff"
				}
				r.printf(strings.Join(parts, "\t") + "\t\n")
			}
		}
	case md.TableRow:
		if entering {
			r.capture(r.out.mode)
		} else {
			// Escape any colors in the row before writing to the
			// tabwriter, otherwise they screw up the width calculations. The
			// escape character for tabwriter is \xff.
			result := r.finishCapture().Bytes()
			result = colorEscapeRe.ReplaceAll(result, []byte("\xff$0\xff"))
			r.write(result)
			r.printf("\n")
		}
	case md.TableCell:
		if !entering {
			r.printf("\t")
		}
	case md.CodeBlock:
		r.depth += 4
		r.renderParagraphKeepBreaks(bytes.NewBuffer(node.Literal))
		r.printf("\n")
		r.depth -= 4
	case md.Document:
	default:
		r.printf("unknown block %s:", node.Type)
		r.write(node.Literal)
	}
	//w.Write([]byte(fmt.Sprintf("node<%s; %t>", node.Type, entering)))
	//w.Write(node.Literal)
	return md.GoToNext
}

// RenderHeader implements blackfriday.Renderer interface.
func (r *Renderer) RenderHeader(w io.Writer, ast *md.Node) {}

// RenderFooter implements blackfriday.Renderer interface.
func (r *Renderer) RenderFooter(w io.Writer, ast *md.Node) {}
