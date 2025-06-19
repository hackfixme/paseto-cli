package cli

import (
	"fmt"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"

	actx "go.hackfix.me/paseto-cli/app/context"
	"go.hackfix.me/paseto-cli/xpaseto"
)

// Parse parses and optionally validates a token.
type Parse struct {
	KeyFile           string              `required:"" short:"k" help:"Path to a key file to verify or decrypt the token (public key for signed tokens, shared key for encrypted tokens)."`
	OutputFormat      xpaseto.TokenFormat `enum:"text,json" env:"PASETO_TOKEN_OUTPUT_FORMAT" default:"text" short:"o" help:"Token output format. Valid values: ${enum}"`
	Validate          bool                `default:"true" negatable:"" help:"Whether to validate the token."`
	TimeSkewTolerance time.Duration       `default:"30s" short:"t" help:"Amount of time to allow token claim times (iat, nbf, exp) to be from the current system time to account for clock skew between systems."`
	Token             string              `arg:"" help:"the token"`
}

// Run the parse command.
func (c *Parse) Run(appCtx *actx.Context) error {
	protocol, err := xpaseto.TokenProtocol(c.Token)
	if err != nil {
		return err
	}

	keyData, err := vfs.ReadFile(appCtx.FS, c.KeyFile)
	if err != nil {
		return fmt.Errorf("failed reading key file '%s': %w", c.KeyFile, err)
	}

	key, err := xpaseto.LoadKey(keyData, protocol.Version(), protocol.Purpose(), xpaseto.KeyTypePublic)
	if err != nil {
		return err
	}

	token, err := xpaseto.ParseToken(key, c.Token)
	if err != nil {
		return err
	}
	if c.Validate {
		err = token.Validate(appCtx.TimeNow, c.TimeSkewTolerance)
		if err != nil {
			return err
		}
	}

	err = token.Write(appCtx.Stdout, c.OutputFormat)
	if err != nil {
		return err
	}

	return nil
}
