package errs

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// NewError returns a new Error for the given format and arguments
func NewError(format string, args ...interface{}) error {
	return errors.Errorf(format, args...)
}

// NewExitError returns an error that the urfave/cli package will handle and
// will show the given error and exit with the given code.
func NewExitError(err error, exitCode int) error {
	return cli.NewExitError(err, exitCode)
}

// Wrap returns a new error wrapped by the given error with the given message.
// If the given error implements the errors.Cause interface, the base error is
// used. If the given error is wrapped by a package name, the error wrapped
// will be the string after the last colon.
func Wrap(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	cause := errors.Cause(err)
	if cause == err {
		str := err.Error()
		if i := strings.LastIndexByte(str, ':'); i >= 0 {
			str = strings.TrimSpace(str[i:])
			return errors.Wrapf(fmt.Errorf(str), format, args...)
		}
	}
	return errors.Wrapf(cause, format, args...)
}

// InsecureCommand returns an error with a message saying that the current
// command requires the insecure flag.
func InsecureCommand(ctx *cli.Context) error {
	return errors.Errorf("'%s %s' requires the '--insecure' flag", ctx.App.Name, ctx.Command.Name)
}

// EqualArguments returns an error saying that the given positional arguments
// cannot be equal.
func EqualArguments(ctx *cli.Context, arg1, arg2 string) error {
	return errors.Errorf("positional arguments <%s> and <%s> cannot be equal in '%s'", arg1, arg2, usage(ctx))
}

// MissingArguments returns an error with a missing arguments message for the
// given positional argument names.
func MissingArguments(ctx *cli.Context, argNames ...string) error {
	switch len(argNames) {
	case 0:
		return errors.Errorf("missing positional arguments in '%s'", usage(ctx))
	case 1:
		return errors.Errorf("missing positional argument <%s> in '%s'", argNames[0], usage(ctx))
	default:
		args := make([]string, len(argNames))
		for i, name := range argNames {
			args[i] = "<" + name + ">"
		}
		return errors.Errorf("missing positional argument %s in '%s'", strings.Join(args, " "), usage(ctx))
	}
}

// NumberOfArguments returns nil if the number of positional arguments is
// equal to the required one. It will return an appropriate error if they are
// not.
func NumberOfArguments(ctx *cli.Context, required int) error {
	n := ctx.NArg()
	switch {
	case n < required:
		return TooFewArguments(ctx)
	case n > required:
		return TooManyArguments(ctx)
	default:
		return nil
	}
}

// TooFewArguments returns an error with a few arguments were provided message.
func TooFewArguments(ctx *cli.Context) error {
	return errors.Errorf("not enough positional arguments were provided in '%s'", usage(ctx))
}

// TooManyArguments returns an error with a too many arguments were provided
// message.
func TooManyArguments(ctx *cli.Context) error {
	return errors.Errorf("too many positional arguments were provided in '%s'", usage(ctx))
}

// InsecureArgument returns an error with the given argument requiring the
// --insecure flag.
func InsecureArgument(ctx *cli.Context, name string) error {
	return errors.Errorf("positional argument <%s> requires the '--insecure' flag", name)
}

// FlagValueInsecure returns an error with the given flag and value requiring
// the --insecure flag.
func FlagValueInsecure(ctx *cli.Context, flag string, value string) error {
	return errors.Errorf("flag '--%s %s' requires the '--insecure' flag", flag, value)
}

// InvalidFlagValue returns an error with the given value being missing or
// invalid for the given flag. Optionally it lists the given formated options
// at the end.
func InvalidFlagValue(ctx *cli.Context, flag string, value string, options string) error {
	var format string
	if len(value) == 0 {
		format = fmt.Sprintf("missing value for flag '--%s'", flag)
	} else {
		format = fmt.Sprintf("invalid value '%s' for flag '--%s'", value, flag)
	}

	if len(options) == 0 {
		return errors.New(format)
	}

	return errors.New(format + "; options are " + options)
}

// IncompatibleFlag returns an error with the flag being incompatible with the
// given value.
func IncompatibleFlag(ctx *cli.Context, flag string, value string) error {
	return errors.Errorf("flag '--%s' is incompatible with '%s'", flag, value)
}

// IncompatibleFlagWithFlag returns an error with the flag being incompatible with the
// given value.
func IncompatibleFlagWithFlag(ctx *cli.Context, flag string, withFlag string) error {
	return errors.Errorf("flag '--%s' is incompatible with '--%s'", flag, withFlag)
}

// IncompatibleFlagValue returns an error with the flag being incompatible with the
// given value.
func IncompatibleFlagValue(ctx *cli.Context, flag, incompatibleWith,
	incompatibleWithValue string) error {
	return errors.Errorf("flag '--%s' is incompatible with flag '--%s %s'",
		flag, incompatibleWith, incompatibleWithValue)
}

// IncompatibleFlagValues returns an error with the flag being incompatible with the
// given value.
func IncompatibleFlagValues(ctx *cli.Context, flag, value, incompatibleWith,
	incompatibleWithValue string) error {
	return errors.Errorf("flag '--%s %s' is incompatible with flag '--%s %s'",
		flag, value, incompatibleWith, incompatibleWithValue)
}

// IncompatibleFlagValueWithFlagValue returns an error with the given value being missing or
// invalid for the given flag. Optionally it lists the given formated options
// at the end.
func IncompatibleFlagValueWithFlagValue(ctx *cli.Context, flag string, value string,
	withFlag string, withValue, options string) error {
	format := fmt.Sprintf("flag '--%s %s' is incompatible with flag '--%s %s'",
		flag, value, withFlag, withValue)

	if len(options) == 0 {
		return errors.New(format)
	}

	return errors.Errorf("%s\n\n  Option(s): --%s %s", format, withFlag, options)
}

// RequiredFlag returns an error with the required flag message.
func RequiredFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("'%s %s' requires the '--%s' flag", ctx.App.HelpName,
		ctx.Command.Name, flag)
}

// RequiredWithFlag returns an error with the required flag message with another flag.
func RequiredWithFlag(ctx *cli.Context, flag, required string) error {
	return errors.Errorf("flag '--%s' requires the '--%s' flag", flag, required)
}

// RequiredWithFlagValue returns an error with the required flag message.
func RequiredWithFlagValue(ctx *cli.Context, flag, value, required string) error {
	return errors.Errorf("'--%s %s' requires the '--%s' flag", flag, value, required)
}

// RequiredInsecureFlag returns an error with the given flag requiring the
// insecure flag message.
func RequiredInsecureFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' requires the '--insecure' flag", flag)
}

// RequiredSubtleFlag returns an error with the given flag requiring the
// subtle flag message..
func RequiredSubtleFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' requires the '--subtle' flag", flag)
}

// RequiredUnlessInsecureFlag returns an error with the required flag message unless
// the insecure flag is used.
func RequiredUnlessInsecureFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' is required unless the '--insecure' flag is provided", flag)
}

// RequiredUnlessFlag returns an error with the required flag message unless
// the specified flag is used.
func RequiredUnlessFlag(ctx *cli.Context, flag, unlessFlag string) error {
	return errors.Errorf("flag '--%s' is required unless the '--%s' flag is provided", flag, unlessFlag)
}

// RequiredUnlessSubtleFlag returns an error with the required flag message unless
// the subtle flag is used.
func RequiredUnlessSubtleFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' is required unless the '--subtle' flag is provided", flag)
}

// RequiredOrFlag returns an error with a list of flags being required messages.
func RequiredOrFlag(ctx *cli.Context, flags ...string) error {
	params := make([]string, len(flags))
	for i, flag := range flags {
		params[i] = "--" + flag
	}
	return errors.Errorf("one of flag %s is required", strings.Join(params, " or "))
}

// MinSizeFlag returns an error with a greater or equal message message for
// the given flag and size.
func MinSizeFlag(ctx *cli.Context, flag string, size string) error {
	return errors.Errorf("flag '--%s' must be greater or equal than %s", flag, size)
}

// MinSizeInsecureFlag returns an error with a requiring --insecure flag
// message with the given flag an size.
func MinSizeInsecureFlag(ctx *cli.Context, flag, size string) error {
	return errors.Errorf("flag '--%s' requires at least %s unless '--insecure' flag is provided", flag, size)
}

// MutuallyExclusiveFlags returns an error with mutually exclusive message for
// the given flags.
func MutuallyExclusiveFlags(ctx *cli.Context, flag1, flag2 string) error {
	return errors.Errorf("flag '--%s' and flag '--%s' are mutually exclusive", flag1, flag2)
}

// usage returns the command usage text if set or a default usage string.
func usage(ctx *cli.Context) string {
	if len(ctx.Command.UsageText) == 0 {
		return fmt.Sprintf("%s %s [command options]", ctx.App.HelpName, ctx.Command.Name)
	}
	// keep just the first line and remove markdown
	lines := strings.Split(ctx.Command.UsageText, "\n")
	return strings.Replace(lines[0], "**", "", -1)
}

// FileError is a wrapper for errors of the os package.
func FileError(err error, filename string) error {
	if err == nil {
		return nil
	}
	switch e := err.(type) {
	case *os.PathError:
		return errors.Errorf("%s %s failed: %v", e.Op, e.Path, e.Err)
	case *os.LinkError:
		return errors.Errorf("%s %s %s failed: %v", e.Op, e.Old, e.New, e.Err)
	case *os.SyscallError:
		return errors.Errorf("%s failed: %v", e.Syscall, e.Err)
	default:
		return Wrap(err, "unexpected error on %s", filename)
	}
}
