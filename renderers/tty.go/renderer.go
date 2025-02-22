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

type Renderer struct{}

func (r *Renderer) RenderNode(w io.Writer, node *sbom.Node, info render.NodeGraphInfo) error {
	if _, err := fmt.Fprintln(w, strings.Repeat(" ", info.Depth)+string(node.Purl())); err != nil {
		return fmt.Errorf("writing to output: %w", err)
	}
	return nil
}
