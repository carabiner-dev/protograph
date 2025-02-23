package tty

import (
	"fmt"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/protograph/options"
	"github.com/carabiner-dev/protograph/render"
)

func New() *Renderer {
	return &Renderer{}
}

var defaultOptions = Options{
	RenderAsciiTree: true,
	Indent:          2,
}

var _ render.NodeRenderer = (*Renderer)(nil)

type Options struct {
	RenderAsciiTree bool
	Indent          int
}

type Renderer struct{}

// DefaultOptions returns the default options of the renderer
func (r *Renderer) DefaultOptions() any {
	return defaultOptions
}

// RenderNode renders a node to the terminal
func (r *Renderer) RenderNode(opts options.Options, node *sbom.Node, info render.NodeGraphInfo) error {
	if opts.Output == nil {
		return fmt.Errorf("no output writer defined")
	}

	localopts, ok := opts.RendererOptions.(Options)
	if !ok {
		localopts = defaultOptions
	}
	s := string(node.Purl())
	if s == "" {
		s = node.Name
	}
	prefix := ""
	if info.Depth > 0 {
		// This renders a tree branch, optionally with ascii lines:
		//
		// │  │  ├ CONTAINS PACKAGE
		// │  │  └ CONTAINS PACKAGE
		//
		branchPrefix := strings.Repeat(" ", localopts.Indent)
		if localopts.RenderAsciiTree {
			branchPrefix += "│ "
		}
		prefix = strings.Repeat(branchPrefix, info.Depth-1)
		prefix += strings.Repeat(" ", localopts.Indent)

		if localopts.RenderAsciiTree {
			if info.IsLast {
				prefix += "└ "
			} else {
				prefix += "├ "
			}
		}
	}

	if _, err := fmt.Fprintf(opts.Output, "%s%s\n", prefix, s); err != nil {
		return fmt.Errorf("writing to output: %w", err)
	}
	return nil
}
