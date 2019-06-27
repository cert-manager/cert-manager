package usage

import (
	"fmt"
	"strings"

	"github.com/urfave/cli"
)

// HelpCommandAction is the action function of the overwritten help command.
var HelpCommandAction = cli.ActionFunc(helpAction)

// HelpCommand overwrites default urfvafe/cli help command to support one or
// multiple subcommands like:
//   step help
//   step help crypto
//   step help crypto jwt
//   step help crypto jwt sign
//   ...
func HelpCommand() cli.Command {
	return cli.Command{
		Name:      "help",
		Aliases:   []string{"h"},
		Usage:     "display help for the specified command or command group",
		ArgsUsage: "[command]",
		Action:    HelpCommandAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "http",
				Usage: "HTTP service address (e.g., ':8080')",
			},
			cli.StringFlag{
				Name:  "html",
				Usage: "The export <directory> for HTML docs.",
			},
			cli.StringFlag{
				Name:  "markdown",
				Usage: "The export <directory> for Markdown docs.",
			},
			cli.BoolFlag{
				Name:  "report",
				Usage: "Writes a JSON report to the HTML docs directory.",
			},
		},
	}
}

func helpAction(ctx *cli.Context) error {
	// use html version
	if ctx.IsSet("http") {
		return httpHelpAction(ctx)
	}

	if ctx.IsSet("html") {
		return htmlHelpAction(ctx)
	}

	if ctx.IsSet("markdown") {
		return markdownHelpAction(ctx)
	}

	args := ctx.Args()
	if args.Present() {
		last := len(args) - 1
		lastName := args[last]
		subcmd := ctx.App.Commands
		parent := createParentCommand(ctx)

		for _, name := range args[:last] {
			for _, cmd := range subcmd {
				if cmd.HasName(name) {
					parent = cmd
					subcmd = cmd.Subcommands
					break
				}
			}
		}

		for _, cmd := range subcmd {
			if cmd.HasName(lastName) {
				cmd.HelpName = fmt.Sprintf("%s %s", ctx.App.HelpName, strings.Join(args, " "))
				parent.HelpName = fmt.Sprintf("%s %s", ctx.App.HelpName, strings.Join(args[:last], " "))

				ctx.Command = cmd
				if len(cmd.Subcommands) == 0 {
					ctx.App = createCliApp(ctx, parent)
					return cli.ShowCommandHelp(ctx, lastName)
				}

				ctx.App = createCliApp(ctx, cmd)
				return cli.ShowCommandHelp(ctx, "")
			}
		}

		return cli.NewExitError(fmt.Sprintf("No help topic for '%s %s'", ctx.App.Name, strings.Join(args, " ")), 3)
	}

	cli.ShowAppHelp(ctx)
	return nil
}

// createParentCommand returns a command representation of the app.
func createParentCommand(ctx *cli.Context) cli.Command {
	return cli.Command{
		Name:        ctx.App.Name,
		HelpName:    ctx.App.HelpName,
		Usage:       ctx.App.Usage,
		UsageText:   ctx.App.UsageText,
		ArgsUsage:   ctx.App.ArgsUsage,
		Description: ctx.App.Description,
		Subcommands: ctx.App.Commands,
		Flags:       ctx.App.Flags,
	}
}

// createCliApp is re-implementation of urfave/cli method (in command.go):
//
//   func (c Command) startApp(ctx *Context) error
//
// It lets us show the subcommands when help is executed like:
//
//   step help foo
//   step help foo bar
//   ...
func createCliApp(ctx *cli.Context, cmd cli.Command) *cli.App {
	app := cli.NewApp()
	app.Metadata = ctx.App.Metadata

	// set the name and usage
	app.Name = cmd.HelpName
	app.HelpName = cmd.HelpName

	app.Usage = cmd.Usage
	app.UsageText = cmd.UsageText
	app.Description = cmd.Description
	app.ArgsUsage = cmd.ArgsUsage

	// set CommandNotFound
	app.CommandNotFound = ctx.App.CommandNotFound
	app.CustomAppHelpTemplate = cmd.CustomHelpTemplate

	// set the flags and commands
	app.Commands = cmd.Subcommands
	app.Flags = cmd.Flags

	app.Version = ctx.App.Version
	app.Compiled = ctx.App.Compiled
	app.Author = ctx.App.Author
	app.Email = ctx.App.Email
	app.Writer = ctx.App.Writer
	app.ErrWriter = ctx.App.ErrWriter

	// Do not show help or version on subcommands
	app.HideHelp = true
	app.HideVersion = true

	// bash completion
	app.EnableBashCompletion = ctx.App.EnableBashCompletion
	if cmd.BashComplete != nil {
		app.BashComplete = cmd.BashComplete
	}

	// set the actions
	app.Before = cmd.Before
	app.After = cmd.After

	if cmd.Action != nil {
		app.Action = cmd.Action
	} else {
		app.Action = helpAction
	}
	app.OnUsageError = cmd.OnUsageError

	app.Setup()
	return app
}
