package usage

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

var usageTextTempl = "   {{.Name}}\n      {{.Usage}} {{if .Required}}(Required){{else}}(Optional){{end}}{{if .Multiple}} (Multiple can be specified){{end}}\n"
var templ *template.Template

func init() {
	templ = template.Must(template.New("usageText").Parse(usageTextTempl))
}

// Argument specifies the Name, Usage, and whether or not an Argument is
// required or not
type Argument struct {
	Required bool
	Multiple bool
	Name     string
	Usage    string
}

// Decorate returns the name of an Argument and decorates it with notation to
// indicate whether its required or not
func (a Argument) Decorate() string {
	name := a.Name
	if a.Multiple {
		name = name + "(s)..."
	}
	if a.Required {
		return fmt.Sprintf("<%s>", name)
	}

	return fmt.Sprintf("[%s]", name)
}

// Arguments is an array of Argument structs that specify which arguments are
// accepted by a Command
type Arguments []Argument

// UsageText returns the value of the UsageText property for a cli.Command for
// these arguments
func (args Arguments) UsageText() string {
	var buf bytes.Buffer
	for _, a := range args {
		data := map[string]interface{}{
			"Name":     a.Decorate(),
			"Multiple": a.Multiple,
			"Required": a.Required,
			"Usage":    a.Usage,
		}

		err := templ.Execute(&buf, data)
		if err != nil {
			panic(fmt.Sprintf("Could not generate args template for %s: %s", a.Name, err))
		}
	}

	return "\n\n" + buf.String()
}

// ArgsUsage returns the value of the ArgsUsage property for a cli.Command for
// these arguments
func (args Arguments) ArgsUsage() string {
	out := ""
	for i, a := range args {
		out += a.Decorate()
		if i < len(args)-1 {
			out += " "
		}
	}

	return out
}

// AppHelpTemplate contains the modified template for the main app
var AppHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .Commands}} <command>{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## DESCRIPTION
{{.Description}}{{end}}{{if .VisibleCommands}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **{{join .Names ", "}}** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}{{end}}

## OPTIONS

{{range $index, $option := .VisibleFlags}}{{if $index}}
{{end}}{{$option}}
{{end}}{{end}}{{if .Copyright}}{{if len .Authors}}

## AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:

{{range $index, $author := .Authors}}{{if $index}}
{{end}}{{$author}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

## ONLINE

This documentation is available online at https://smallstep.com/docs/cli

## VERSION

{{.Version}}{{end}}{{end}}

## COPYRIGHT

{{.Copyright}}
{{end}}
`

// SubcommandHelpTemplate contains the modified template for a sub command
// Note that the weird "|||\n|---|---|" syntax sets up a markdown table with empty headers.
var SubcommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}** <command>{{if .VisibleFlags}} _[options]_{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## DESCRIPTION

{{.Description}}{{end}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **{{join .Names ", "}}** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`

// CommandHelpTemplate contains the modified template for a command
var CommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .VisibleFlags}} _[options]_{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Category}}

## CATEGORY

{{.Category}}{{end}}{{if .Description}}

## DESCRIPTION

{{.Description}}{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`

// FlagNamePrefixer converts a full flag name and its placeholder into the help
// message flag prefix. This is used by the default FlagStringer.
//
// This method clones urflave/cli functionality but adds a new line at the end.
func FlagNamePrefixer(fullName, placeholder string) string {
	var prefixed string
	parts := strings.Split(fullName, ",")
	for i, name := range parts {
		name = strings.Trim(name, " ")
		prefixed += "**" + prefixFor(name) + name + "**"

		if placeholder != "" {
			prefixed += "=" + placeholder
		}
		if i < len(parts)-1 {
			prefixed += ", "
		}
	}
	//return "* " + prefixed + "\n"
	return prefixed + "\n: "
}

func prefixFor(name string) (prefix string) {
	if len(name) == 1 {
		prefix = "-"
	} else {
		prefix = "--"
	}

	return
}
