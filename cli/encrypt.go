package cli

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/alecthomas/kong"
	"github.com/mandelsoft/vfs/pkg/vfs"

	actx "go.hackfix.me/paseto-cli/app/context"
	"go.hackfix.me/paseto-cli/xpaseto"
)

// Encrypt generates a new encrypted token.
type Encrypt struct {
	ProtocolVersion ProtocolVersionOption `default:"4" env:"PASETO_VERSION" short:"v" help:"Version of the PASETO protocol. Valid values: 2,3,4"`
	KeyFile         string                `required:"" short:"k" help:"Path to a symmetric key file to encrypt the token."`
	Expiration      time.Time             `env:"PASETO_TOKEN_EXPIRATION" default:"1h" short:"e" type:"expiration" help:"Token expiration as a duration from now (e.g. 5m, 1h, 3d, 1M3d, 1Y) or a future timestamp in RFC 3339 format (e.g. %s)."`
	Claims          ClaimsOption          `name:"claim" placeholder:"CLAIM" type:"claims" short:"c" help:"key=value pair to add to the token (e.g. role=admin), or '-' to read claims as JSON from stdin. Can be specified multiple times."`
}

// Run the encrypt command.
func (c *Encrypt) Run(kctx *kong.Context, appCtx *actx.Context) error {
	keyData, err := vfs.ReadFile(appCtx.FS, c.KeyFile)
	if err != nil {
		return fmt.Errorf("failed reading key file '%s': %w", c.KeyFile, err)
	}
	key, err := xpaseto.LoadKey(keyData, paseto.Version(c.ProtocolVersion), paseto.Local, xpaseto.KeyTypeSymmetric)
	if err != nil {
		return err
	}

	expSet := isExpirationSet(kctx.Args)
	claims := mergeClaims(c.Claims.fromArgs, c.Claims.fromStdin, c.Expiration, expSet)
	token, err := xpaseto.NewToken(appCtx.TimeNow, claims...)
	if err != nil {
		return err
	}
	tokenEncrypted, err := key.Encrypt(token)
	if err != nil {
		return err
	}
	fmt.Fprintln(appCtx.Stdout, tokenEncrypted)

	return nil
}
