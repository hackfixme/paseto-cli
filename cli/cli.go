package cli

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/paseto-cli/app/context"
)

// CLI is the command line interface of PASETO.
type CLI struct {
	kong   *kong.Kong
	kctx   *kong.Context
	appCtx *actx.Context

	Genkey  GenKey  `kong:"cmd,help='Generate new keys.'"`
	Encrypt Encrypt `kong:"cmd,help='Generate a new encrypted token.'"`
	Sign    Sign    `kong:"cmd,help='Generate a new signed token.'"`
	Parse   Parse   `kong:"cmd,help='Parse and optionally validate a token.'"`

	Log struct {
		Level slog.Level `enum:"DEBUG,INFO,WARN,ERROR" default:"INFO" help:"Set the app logging level."`
	} `embed:"" prefix:"log-"`
	Version kong.VersionFlag `env:"-" help:"Output version and exit."`
}

// New initializes the command-line interface.
func New(appCtx *actx.Context, version string) (*CLI, error) {
	c := &CLI{appCtx: appCtx}
	kparser, err := kong.New(c,
		kong.Name("paseto"),
		kong.UsageOnError(),
		kong.DefaultEnvars("PASETO"),
		kong.NamedMapper("claims", ClaimsMapper{stdin: appCtx.Stdin}),
		kong.NamedMapper("expiration", &ExpirationMapper{time: appCtx.Time}),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:             true,
			Summary:             true,
			NoExpandSubcommands: true,
		}),
		kong.ValueFormatter(func(value *kong.Value) string {
			if value.Name == "expiration" {
				y, m, d := appCtx.Time.Now().Date()
				exampleExp := time.Date(y, m, d+1, 0, 0, 0, 0, appCtx.Time.Now().Location())
				value.Help = fmt.Sprintf(value.OrigHelp, exampleExp.Format(time.RFC3339))
			}
			return value.Help
		}),
		kong.Vars{
			"version": version,
		},
	)
	if err != nil {
		return nil, err
	}

	c.kong = kparser

	return c, nil
}

// Execute starts the command execution. Parse must be called before this method.
func (c *CLI) Execute(appCtx *actx.Context) error {
	if c.kctx == nil {
		panic("the CLI wasn't initialized properly")
	}
	c.kong.Stdout = appCtx.Stdout
	c.kong.Stderr = appCtx.Stderr

	return c.kctx.Run(appCtx)
}

// ParseArgs parses the given command line arguments. This method must be called
// before Execute.
func (c *CLI) ParseArgs(args []string) error {
	kctx, err := c.kong.Parse(args)
	if err != nil {
		return err
	}
	c.kctx = kctx

	return nil
}

// Command returns the full path of the executed command.
func (c *CLI) Command() string {
	if c.kctx == nil {
		panic("the CLI wasn't initialized properly")
	}
	cmdPath := []string{}
	for _, p := range c.kctx.Path {
		if p.Command != nil {
			cmdPath = append(cmdPath, p.Command.Name)
		}
	}

	return strings.Join(cmdPath, " ")
}
