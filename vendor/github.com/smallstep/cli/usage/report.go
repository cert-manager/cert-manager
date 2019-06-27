package usage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Section keeps track of individual sections
type Section struct {
	Command  string     `json:"command"`
	Name     string     `json:"name"`
	Text     string     `json:"text"`
	Words    int        `json:"words"`
	Lines    int        `json:"lines"`
	Sections []*Section `json:"sections"`
}

// Report holds together a report of sections
type Report struct {
	Report []*Section `json:"report"`
}

// NewReport returns report based on raw
func NewReport(command string, top []byte) *Report {
	report := Report{}
	report.Process(command, top)

	return &report
}

// Write serializes the report to json
func (report *Report) Write(w io.Writer) error {
	j, err := json.MarshalIndent(report, "", "  ")

	if err != nil {
		return err
	}

	w.Write(j)

	return nil
}

// Process adds a html based help page to the report
func (report *Report) Process(command string, raw []byte) error {
	r := bytes.NewBuffer(raw)
	doc, err := html.Parse(r)

	if err != nil {
		return err
	}

	if doc.FirstChild.Type != html.ElementNode ||
		doc.FirstChild.Data != "html" ||
		doc.FirstChild.FirstChild.NextSibling.Data != "body" {
		return errors.New("error parsing raw html")
	}

	body := doc.FirstChild.FirstChild.NextSibling

	report.addSection(command, body.FirstChild, nil)

	return nil
}

func (report *Report) addSection(command string, node *html.Node, section *Section) (*html.Node, *Section) {
	if node == nil ||
		node.Type != html.ElementNode ||
		node.Data != "h2" {
		return nil, nil
	}

	text, next := report.processNode(node)
	words := strings.Fields(text)
	lines := strings.Split(text, "\n")

	s := Section{
		Command: command,
		Name:    node.FirstChild.Data,
		Text:    text,
		Words:   len(words),
		Lines:   len(lines),
	}

	if section == nil {
		report.Report = append(report.Report, &s)
		return report.addSection(command, next, &s)
	}

	section.Sections = append(section.Sections, &s)
	return report.addSection(command, next, section)
}

func (report *Report) processNode(node *html.Node) (string, *html.Node) {
	text := ""
	current := node.NextSibling

	r, _ := regexp.Compile("<[^>]*>")

	for current != nil {
		var buf bytes.Buffer
		w := io.Writer(&buf)
		html.Render(w, current)

		notags := r.ReplaceAllString(buf.String(), "")
		clean := strings.TrimSpace(notags)

		if len(text) > 0 && len(clean) > 0 {
			text = fmt.Sprintf("%s %s", text, clean)
		} else if len(clean) > 0 {
			text = clean
		}

		current = current.NextSibling
		if current == nil {
			return text, nil
		} else if current.Type == html.ElementNode &&
			current.Data == "h2" {
			node = current
			current = nil
		}
	}

	return text, node
}

// PerHeadline returns all sections across commands/pages with the same headline
func (report *Report) PerHeadline(headline string) []Section {
	var results []Section
	for _, top := range report.Report {
		for _, section := range top.Sections {
			if section.Name != headline {
				continue
			}

			results = append(results, *section)
		}
	}

	return results
}
