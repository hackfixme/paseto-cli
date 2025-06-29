package app

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mandelsoft/vfs/pkg/vfs"

	actx "go.hackfix.me/paseto-cli/app/context"
)

// Option is a function that allows configuring the application.
type Option func(*App)

// WithContext sets the main context.
func WithContext(ctx context.Context) Option {
	return func(app *App) {
		app.ctx.Ctx = ctx
	}
}

// WithEnv sets the process environment used by the application.
func WithEnv(env actx.Environment) Option {
	return func(app *App) {
		app.ctx.Env = env
	}
}

// WithFDs sets the file descriptors used by the application.
func WithFDs(stdin io.Reader, stdout, stderr io.Writer) Option {
	return func(app *App) {
		app.ctx.Stdin = stdin
		app.ctx.Stdout = stdout
		app.ctx.Stderr = stderr
	}
}

// WithFS sets the filesystem used by the application.
func WithFS(fs vfs.FileSystem) Option {
	return func(app *App) {
		app.ctx.FS = fs
	}
}

// WithLogger initializes the logger used by the application.
func WithLogger(isStdoutTTY, isStderrTTY bool) Option {
	return func(app *App) {
		lvl := &slog.LevelVar{}
		lvl.Set(slog.LevelInfo)
		logger := slog.New(
			tint.NewHandler(app.ctx.Stderr, &tint.Options{
				Level:      lvl,
				NoColor:    !isStderrTTY,
				TimeFormat: "2006-01-02 15:04:05.000",
			}),
		)
		app.logLevel = lvl
		app.ctx.Logger = logger
		slog.SetDefault(logger)
	}
}

// WithTimeNow sets the function used to retrieve the current system time.
func WithTimeNow(timeNowFn func() time.Time) Option {
	return func(app *App) {
		app.ctx.TimeNow = timeNowFn
	}
}
