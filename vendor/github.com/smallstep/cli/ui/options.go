package ui

import (
	"github.com/manifoldco/promptui"
)

type options struct {
	mask            rune
	defaultValue    string
	value           string
	allowEdit       bool
	printTemplate   string
	promptTemplates *promptui.PromptTemplates
	selectTemplates *promptui.SelectTemplates
	validateFunc    promptui.ValidateFunc
}

// apply applies the given options.
func (o *options) apply(opts []Option) *options {
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// getValue validates the value and returns it.
func (o *options) getValue() (string, error) {
	if o.validateFunc == nil {
		return o.value, nil
	}
	if err := o.validateFunc(o.value); err != nil {
		return "", err
	}
	return o.value, nil
}

// getValueBytes validates the value and returns it as a byte slice.
func (o *options) getValueBytes() ([]byte, error) {
	if o.validateFunc == nil {
		return []byte(o.value), nil
	}
	if err := o.validateFunc(o.value); err != nil {
		return nil, err
	}
	return []byte(o.value), nil
}

// Option is the type of the functions that modify the prompt options.
type Option func(*options)

// WithMask adds a mask to a prompt.
func WithMask(r rune) Option {
	return func(o *options) {
		o.mask = r
	}
}

// WithDefaultValue adds a custom string as the default value.
func WithDefaultValue(s string) Option {
	return func(o *options) {
		o.defaultValue = s
	}
}

// WithValue sets a custom string as the result of a prompt. If value is set,
// the prompt won't be displayed.
func WithValue(value string) Option {
	return func(o *options) {
		o.value = value
	}
}

// WithAllowEdit if true, let's the user edit the default value set.
func WithAllowEdit(b bool) Option {
	return func(o *options) {
		o.allowEdit = b
	}
}

// WithPrintTemplate sets the template to use on the print methods.
func WithPrintTemplate(template string) Option {
	return func(o *options) {
		o.printTemplate = template
	}
}

// WithPromptTemplates adds a custom template to a prompt.
func WithPromptTemplates(t *promptui.PromptTemplates) Option {
	return func(o *options) {
		o.promptTemplates = t
	}
}

// WithSelectTemplates adds a custom template to a select.
func WithSelectTemplates(t *promptui.SelectTemplates) Option {
	return func(o *options) {
		o.selectTemplates = t
	}
}

// WithValidateFunc adds a custom validation function to a prompt.
func WithValidateFunc(fn func(string) error) Option {
	return func(o *options) {
		o.validateFunc = fn
	}
}

// WithValidateNotEmpty adds a custom validation function to a prompt that
// checks that the propted string is not empty.
func WithValidateNotEmpty() Option {
	return WithValidateFunc(NotEmpty())
}

// WithValidateYesNo adds a custom validation function to a prompt for a Yes/No
// prompt.
func WithValidateYesNo() Option {
	return WithValidateFunc(YesNo())
}

// WithRichPrompt add the template option with rich templates.
func WithRichPrompt() Option {
	return WithPromptTemplates(PromptTemplates())
}

// WithSimplePrompt add the template option with simple templates.
func WithSimplePrompt() Option {
	return WithPromptTemplates(SimplePromptTemplates())
}
