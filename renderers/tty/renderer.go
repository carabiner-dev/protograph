package tty

import (
	"fmt"
	"io"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/protograph/render"
)

func New() *Renderer {
	return &Renderer{}
}

var _ render.NodeRenderer = (*Renderer)(nil)

type Renderer struct{}

func (r *Renderer) RenderNode(w io.Writer, node *sbom.Node, info render.NodeGraphInfo) error {
	s := string(node.Purl())
	if s == "" {
		s = node.Name
	}
	if _, err := fmt.Fprintln(w, strings.Repeat(" ", info.Depth)+s+fmt.Sprintf(" (%d descendants)", len(info.Descendants.Nodes)-1)); err != nil {
		return fmt.Errorf("writing to output: %w", err)
	}
	return nil
}
