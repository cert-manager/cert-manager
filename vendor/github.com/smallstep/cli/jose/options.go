package jose

import (
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
)

type context struct {
	use, alg, kid    string
	subtle, insecure bool
	noDefaults       bool
	password         []byte
	uiOptions        []ui.Option
}

// apply the options to the context and returns an error if one of the options
// fails.
func (ctx *context) apply(opts ...Option) (*context, error) {
	for _, opt := range opts {
		if err := opt(ctx); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}

// Option is the type used to add attributes to the context.
type Option func(ctx *context) error

// WithUse adds the use claim to the context.
func WithUse(use string) Option {
	return func(ctx *context) error {
		ctx.use = use
		return nil
	}
}

// WithAlg adds the alg claim to the context.
func WithAlg(alg string) Option {
	return func(ctx *context) error {
		ctx.alg = alg
		return nil
	}
}

// WithKid adds the kid property to the context.
func WithKid(kid string) Option {
	return func(ctx *context) error {
		ctx.kid = kid
		return nil
	}
}

// WithSubtle marks the context as subtle.
func WithSubtle(subtle bool) Option {
	return func(ctx *context) error {
		ctx.subtle = subtle
		return nil
	}
}

// WithInsecure marks the context as insecure.
func WithInsecure(insecure bool) Option {
	return func(ctx *context) error {
		ctx.insecure = insecure
		return nil
	}
}

// WithNoDefaults avoids that the parser loads defaults values, specially the
// default algorithms.
func WithNoDefaults(val bool) Option {
	return func(ctx *context) error {
		ctx.noDefaults = val
		return nil
	}
}

// WithPassword is a method that adds the given password to the context.
func WithPassword(pass []byte) Option {
	return func(ctx *context) error {
		ctx.password = pass
		return nil
	}
}

// WithPasswordFile is a method that adds the password in a file to the context.
func WithPasswordFile(filename string) Option {
	return func(ctx *context) error {
		b, err := utils.ReadPasswordFromFile(filename)
		if err != nil {
			return err
		}
		ctx.password = b
		return nil
	}
}

// WithUIOptions adds UI package options to the password prompts.
func WithUIOptions(opts ...ui.Option) Option {
	return func(ctx *context) error {
		ctx.uiOptions = opts
		return nil
	}
}
