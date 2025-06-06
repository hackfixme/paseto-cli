package cli

import (
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/alecthomas/kong"
	"github.com/mandelsoft/vfs/pkg/vfs"

	actx "go.hackfix.me/paseto-cli/app/context"
	"go.hackfix.me/paseto-cli/xpaseto"
)

// Sign generates a new signed token.
type Sign struct {
	ProtocolVersion ProtocolVersionOption `default:"4" env:"PASETO_VERSION" short:"v" help:"Version of the PASETO protocol. Valid values: 2,3,4"`
	KeyFile         string                `required:"" short:"k" help:"Path to a private key file to sign the token."`
	Expiration      time.Time             `env:"PASETO_TOKEN_EXPIRATION" default:"1h" short:"e" type:"expiration" help:"Token expiration as a duration from now (e.g. 5m, 1h, 3d, 1M3d, 1Y) or a future timestamp in RFC 3339 format (e.g. %s)."`
	Claims          ClaimsOption          `name:"claim" placeholder:"CLAIM" type:"claims" short:"c" help:"key=value pair to add to the token (e.g. role=admin), or '-' to read claims as JSON from stdin. Can be specified multiple times."`
}

// Run the sign command.
func (c *Sign) Run(kctx *kong.Context, appCtx *actx.Context) error {
	keyData, err := vfs.ReadFile(appCtx.FS, c.KeyFile)
	if err != nil {
		return fmt.Errorf("failed reading key file '%s': %w", c.KeyFile, err)
	}
	key, err := xpaseto.LoadKey(keyData, paseto.Version(c.ProtocolVersion), paseto.Public, xpaseto.KeyTypePrivate)
	if err != nil {
		return err
	}

	expSet := isExpirationSet(kctx.Args)
	claims := mergeClaims(c.Claims.fromArgs, c.Claims.fromStdin, c.Expiration, expSet)
	token, err := xpaseto.NewToken(appCtx.Time, claims...)
	if err != nil {
		return err
	}
	tokenSigned, err := key.Sign(token)
	if err != nil {
		return err
	}
	fmt.Fprintln(appCtx.Stdout, tokenSigned)

	return nil
}

// HACK: Determine whether the expiration flag was set by the user or not.
// This doesn't seem possible with kong, see https://github.com/alecthomas/kong/issues/365
// I did try using a custom Mapper and checking kong.DecodeContext.Value.Set, which
// seems relevant, but I couldn't get it to work.
func isExpirationSet(args []string) bool {
	expArgs := []string{"--expiration", "-e"}
	for _, arg := range args {
		for _, earg := range expArgs {
			if strings.HasPrefix(arg, earg) {
				return true
			}
		}
	}
	return false
}
