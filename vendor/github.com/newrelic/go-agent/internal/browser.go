package internal

import "bytes"

// BrowserAttributes returns a string with the attributes that are attached to
// the browser destination encoded in the JSON format expected by the Browser
// agent.
func BrowserAttributes(a *Attributes) []byte {
	buf := &bytes.Buffer{}

	buf.WriteString(`{"u":`)
	userAttributesJSON(a, buf, destBrowser, nil)
	buf.WriteString(`,"a":`)
	agentAttributesJSON(a, buf, destBrowser)
	buf.WriteByte('}')

	return buf.Bytes()
}
