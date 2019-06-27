package ui

import (
	"fmt"

	"github.com/manifoldco/promptui"
)

var (
	// IconInitial is the icon used when starting in prompt mode and the icon next to the label when
	// starting in select mode.
	IconInitial = promptui.Styler(promptui.FGBlue)("?")

	// IconGood is the icon used when a good answer is entered in prompt mode.
	IconGood = promptui.Styler(promptui.FGGreen)("✔")

	// IconWarn is the icon used when a good, but potentially invalid answer is entered in prompt mode.
	IconWarn = promptui.Styler(promptui.FGYellow)("⚠")

	// IconBad is the icon used when a bad answer is entered in prompt mode.
	IconBad = promptui.Styler(promptui.FGRed)("✗")

	// IconSelect is the icon used to identify the currently selected item in select mode.
	IconSelect = promptui.Styler(promptui.FGBold)("▸")
)

// PrintSelectedTemplate returns the default template used in PrintSelected.
func PrintSelectedTemplate() string {
	return fmt.Sprintf(`{{ "%s" | green }} {{ .Name | bold }}{{ ":" | bold }} {{ .Value }}`, IconGood) + "\n"
}

// PromptTemplates is the default style for a prompt.
func PromptTemplates() *promptui.PromptTemplates {
	bold := promptui.Styler(promptui.FGBold)
	return &promptui.PromptTemplates{
		Prompt:  fmt.Sprintf("%s {{ . | bold }}%s ", IconInitial, bold(":")),
		Success: fmt.Sprintf("%s {{ . | bold }}%s ", bold(IconGood), bold(":")),
		// Confirm: fmt.Sprintf(`{{ "%s" | bold }} {{ . | bold }}? {{ "[]" | faint }} `, IconInitial),
		Valid:   fmt.Sprintf("%s {{ . | bold }}%s ", bold(IconGood), bold(":")),
		Invalid: fmt.Sprintf("%s {{ . | bold }}%s ", bold(IconBad), bold(":")),
	}
}

// SimplePromptTemplates is a prompt with a simple style, used by default on password prompts.
func SimplePromptTemplates() *promptui.PromptTemplates {
	return &promptui.PromptTemplates{
		Prompt:  "{{ . }}: ",
		Success: "{{ . }}: ",
		Valid:   "{{ . }}: ",
		Invalid: "{{ . }}: ",
	}
}

// SelectTemplates returns the default promptui.SelectTemplate for string
// slices. The given name is the prompt of the selected option.
func SelectTemplates(name string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    fmt.Sprintf("%s {{ . }}: ", IconInitial),
		Active:   fmt.Sprintf("%s {{ . | underline }}", IconSelect),
		Inactive: "  {{ . }}",
		Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "%s:" | bold }} {{ .Name }}`, IconGood, name),
	}
}

// NamedSelectTemplates returns the default promptui.SelectTemplate for struct
// slices with a name property. The given name is the prompt of the selected
// option.
func NamedSelectTemplates(name string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    fmt.Sprintf("%s {{.Name}}: ", IconInitial),
		Active:   fmt.Sprintf("%s {{ .Name | underline }}", IconSelect),
		Inactive: "  {{.Name}}",
		Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "%s:" | bold }} {{ .Name }}`, IconGood, name),
	}
}
