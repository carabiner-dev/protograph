package tty

import (
	"fmt"
	"io"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/protograph/render"
)

func New() *Renderer {
	return &Renderer{
		Options: defaultOptions,
	}
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

type Renderer struct {
	Options
}

func (r *Renderer) RenderNode(w io.Writer, node *sbom.Node, info render.NodeGraphInfo) error {
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
		branchPrefix := strings.Repeat(" ", r.Options.Indent)
		if r.Options.RenderAsciiTree {
			branchPrefix += "│ "
		}
		prefix = strings.Repeat(branchPrefix, info.Depth-1)
		prefix += strings.Repeat(" ", r.Options.Indent)

		if r.Options.RenderAsciiTree {
			if info.IsLast {
				prefix += "└ "
			} else {
				prefix += "├ "
			}
		}
	}

	if _, err := fmt.Fprintf(w, "%s%s\n", prefix, s); err != nil {
		return fmt.Errorf("writing to output: %w", err)
	}
	return nil
}
