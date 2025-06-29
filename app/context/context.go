package context

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"
)

// Context contains common objects used by the application. It is passed around
// the application to avoid direct dependencies on external systems, and make
// testing easier.
type Context struct {
	Ctx     context.Context // global context
	FS      vfs.FileSystem  // filesystem
	Env     Environment     // process environment
	Logger  *slog.Logger    // global logger
	TimeNow func() time.Time

	// Standard streams
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Metadata
	Version *VersionInfo
}
