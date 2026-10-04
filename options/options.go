package options

import (
	"io"
	"os"
)

type Options struct {
	// SortPackagesFiles walks a node's packages before its files. Within
	// each, and without it across both, siblings are walked by name, then
	// version, then id: always the same order for the same graph.
	SortPackagesFiles bool
	RenderFiles       bool
	RenderPackages    bool
	FullTree          bool // When true, show full subtree for every node occurrence; when false (default), only first occurrence shows children
	Output            io.Writer
	RendererOptions   any
}

var Default = Options{
	SortPackagesFiles: true,
	RenderFiles:       true,
	RenderPackages:    true,
	Output:            os.Stdout,
}
