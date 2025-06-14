package cli

import (
	"fmt"
	"io"

	"aidanwoods.dev/go-paseto"

	actx "go.hackfix.me/paseto-cli/app/context"
	"go.hackfix.me/paseto-cli/xpaseto"
)

// GenKey generates new keys.
type GenKey struct {
	ProtocolVersion ProtocolVersionOption `default:"4" env:"PASETO_VERSION" short:"v" help:"Version of the PASETO protocol. Valid values: 2,3,4"`
	ProtocolPurpose paseto.Purpose        `arg:"" enum:"local,public" required:"" help:"PASETO protocol purpose; \"local\" for shared-key (symmetric) encryption or \"public\" for public-key (asymmetric) signing."`
	OutFile         string                `env:"PASETO_KEY_OUT_FILE" short:"o" help:"Base file path to write the key(s) to; stdout will be used if not specified."`
	Encoding        xpaseto.KeyEncoding   `env:"PASETO_KEY_ENCODING" enum:"hex,pem" default:"hex" short:"e" help:"Encoding type. Valid values: ${enum}"`
}

// Run the genkey command.
func (c *GenKey) Run(appCtx *actx.Context) error {
	key, err := xpaseto.NewKey(paseto.Version(c.ProtocolVersion), c.ProtocolPurpose, nil)
	if err != nil {
		return err
	}

	err = writeKey(appCtx, key, c.OutFile, c.Encoding)
	if err != nil {
		return err
	}
	pubKey := key.Public()
	if pubKey != nil {
		err = writeKey(appCtx, pubKey, c.OutFile, c.Encoding)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeKey(appCtx *actx.Context, k *xpaseto.Key, outFile string, enc xpaseto.KeyEncoding) error {
	var (
		w     io.Writer
		path  string
		extra bool
	)
	if outFile == "" {
		w = appCtx.Stdout
		extra = true
	} else {
		path = fmt.Sprintf("%s-%s.key", outFile, k.Type().Short())
		f, err := appCtx.FS.Create(path)
		if err != nil {
			return fmt.Errorf("failed opening file for writing key: %w", err)
		}
		defer f.Close()
		w = f
	}

	return k.Write(w, enc, extra)
}
