package main

import (
	"os"
	"time"

	"github.com/mandelsoft/vfs/pkg/osfs"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"

	"go.hackfix.me/paseto-cli/app"
	actx "go.hackfix.me/paseto-cli/app/context"
	aerrors "go.hackfix.me/paseto-cli/app/errors"
)

func main() {
	a, err := app.New("paseto",
		app.WithTimeNow(time.Now),
		app.WithEnv(osEnv{}),
		app.WithFDs(
			os.Stdin,
			colorable.NewColorable(os.Stdout),
			colorable.NewColorable(os.Stderr),
		),
		app.WithFS(osfs.New()),
		app.WithLogger(
			isatty.IsTerminal(os.Stdout.Fd()),
			isatty.IsTerminal(os.Stderr.Fd()),
		),
	)
	if err != nil {
		aerrors.Errorf(err)
		os.Exit(1)
	}
	if err = a.Run(os.Args[1:]); err != nil {
		aerrors.Errorf(err)
		os.Exit(1)
	}
}

type osEnv struct{}

var _ actx.Environment = (*osEnv)(nil)

func (e osEnv) Get(key string) string {
	return os.Getenv(key)
}

func (e osEnv) Set(key, val string) error {
	return os.Setenv(key, val)
}
