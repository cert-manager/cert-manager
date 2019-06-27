package ui

import (
	"fmt"
	"os"
	"syscall"
	"text/template"

	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
)

// stderr implements an io.WriteCloser that skips the terminal bell character
// (ASCII code 7), and writes the rest to os.Stderr. It's used to replace
// readline.Stdout, that is the package used by promptui to display the prompts.
type stderr struct{}

// Write implements an io.WriterCloser over os.Stderr, but it skips the terminal
// bell character.
func (s *stderr) Write(b []byte) (int, error) {
	if len(b) == 1 && b[0] == readline.CharBell {
		return 0, nil
	}
	return os.Stderr.Write(b)
}

// Close implements an io.WriterCloser over os.Stderr.
func (s *stderr) Close() error {
	return os.Stderr.Close()
}

func init() {
	readline.Stdout = &stderr{}
}

// Printf uses templates to print the string formated to os.Stderr.
func Printf(format string, args ...interface{}) error {
	text := fmt.Sprintf(format, args...)
	t, err := template.New("Printf").Funcs(promptui.FuncMap).Parse(text)
	if err != nil {
		return errors.Wrap(err, "error parsing template")
	}
	if err := t.Execute(os.Stderr, nil); err != nil {
		return errors.Wrap(err, "error executing template")
	}
	return nil
}

// Println uses templates to print the given arguments to os.Stderr
func Println(args ...interface{}) error {
	text := fmt.Sprintln(args...)
	t, err := template.New("Println").Funcs(promptui.FuncMap).Parse(text)
	if err != nil {
		return errors.Wrap(err, "error parsing template")
	}
	if err := t.Execute(os.Stderr, nil); err != nil {
		return errors.Wrap(err, "error executing template")
	}
	return nil
}

// PrintSelected prints the given name and value as if they were selected from a
// promptui.Select.
func PrintSelected(name, value string, opts ...Option) error {
	o := &options{
		printTemplate: PrintSelectedTemplate(),
	}
	o.apply(opts)

	t, err := template.New(name).Funcs(promptui.FuncMap).Parse(o.printTemplate)
	if err != nil {
		return errors.Wrap(err, "error parsing template")
	}

	data := struct {
		Name  string
		Value string
	}{name, value}
	if err := t.Execute(os.Stderr, data); err != nil {
		return errors.Wrap(err, "error executing template")
	}

	return nil
}

// Prompt creates a runs a promptui.Prompt with the given label.
func Prompt(label string, opts ...Option) (string, error) {
	o := &options{
		promptTemplates: PromptTemplates(),
	}
	o.apply(opts)

	// Return value if set
	if o.value != "" {
		return o.getValue()
	}

	// Prompt using the terminal
	clean, err := preparePromptTerminal()
	if err != nil {
		return "", err
	}
	defer clean()

	prompt := &promptui.Prompt{
		Label:     label,
		Default:   o.defaultValue,
		AllowEdit: o.allowEdit,
		Validate:  o.validateFunc,
		Templates: o.promptTemplates,
	}
	value, err := prompt.Run()
	if err != nil {
		return "", errors.Wrap(err, "error running prompt")
	}
	return value, nil
}

// PromptPassword creates a runs a promptui.Prompt with the given label. This
// prompt will mask the key entries with \r.
func PromptPassword(label string, opts ...Option) ([]byte, error) {
	// Using a not printable character as they work better than \r
	o := &options{
		mask:            1,
		promptTemplates: SimplePromptTemplates(),
	}
	o.apply(opts)

	// Return value if set
	if o.value != "" {
		return o.getValueBytes()
	}

	// Prompt using the terminal
	clean, err := preparePromptTerminal()
	if err != nil {
		return nil, err
	}
	defer clean()

	prompt := &promptui.Prompt{
		Label:     label,
		Mask:      o.mask,
		Default:   o.defaultValue,
		AllowEdit: o.allowEdit,
		Validate:  o.validateFunc,
		Templates: o.promptTemplates,
	}
	pass, err := prompt.Run()
	if err != nil {
		return nil, errors.Wrap(err, "error reading password")
	}
	return []byte(pass), nil
}

// PromptPasswordGenerate creaes a runs a promptui.Prompt with the given label.
// This prompt will mask the key entries with \r. If the result password length
// is 0, it will generate a new prompt with a generated password that can be
// edited.
func PromptPasswordGenerate(label string, opts ...Option) ([]byte, error) {
	pass, err := PromptPassword(label, opts...)
	if err != nil || len(pass) > 0 {
		return pass, err
	}
	passString, err := randutil.ASCII(32)
	if err != nil {
		return nil, err
	}
	passString, err = Prompt("Password", WithDefaultValue(passString), WithAllowEdit(true), WithValidateNotEmpty())
	if err != nil {
		return nil, err
	}
	return []byte(passString), nil
}

// Select creates and runs a promptui.Select with the given label and items.
func Select(label string, items interface{}, opts ...Option) (int, string, error) {
	o := &options{
		selectTemplates: SelectTemplates(label),
	}
	o.apply(opts)

	clean, err := prepareSelectTerminal()
	if err != nil {
		return 0, "", err
	}
	defer clean()

	prompt := &promptui.Select{
		Label:     label,
		Items:     items,
		Templates: o.selectTemplates,
	}
	n, s, err := prompt.Run()
	if err != nil {
		return 0, "", errors.Wrap(err, "error running prompt")
	}
	return n, s, nil
}

func preparePromptTerminal() (func(), error) {
	nothing := func() {}
	if !readline.IsTerminal(syscall.Stdin) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nothing, errors.Wrap(err, "error allocating terminal")
		}
		clean := func() {
			tty.Close()
		}

		fd := int(tty.Fd())
		state, err := readline.MakeRaw(fd)
		if err != nil {
			defer clean()
			return nothing, errors.Wrap(err, "error making raw terminal")
		}
		stdin := readline.Stdin
		readline.Stdin = tty
		clean = func() {
			readline.Stdin = stdin
			readline.Restore(fd, state)
			tty.Close()
		}
		return clean, nil
	}

	return nothing, nil
}

func prepareSelectTerminal() (func(), error) {
	nothing := func() {}
	if !readline.IsTerminal(syscall.Stdin) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nothing, errors.Wrap(err, "error allocating terminal")
		}
		clean := func() {
			tty.Close()
		}

		fd := int(tty.Fd())
		state, err := readline.MakeRaw(fd)
		if err != nil {
			defer clean()
			return nothing, errors.Wrap(err, "error making raw terminal")
		}
		stdin := os.Stdin
		os.Stdin = tty
		clean = func() {
			os.Stdin = stdin
			readline.Restore(fd, state)
			tty.Close()
		}
		return clean, nil
	}

	return nothing, nil
}
