package options

import (
	"io"
	"os"
)

type Options struct {
	SortPackagesFiles bool
	RenderFiles       bool
	RenderPackages    bool
	Output            io.Writer
	RendererOptions   any
}

var Default = Options{
	SortPackagesFiles: true,
	RenderFiles:       true,
	RenderPackages:    true,
	Output:            os.Stdout,
}
