package render

import (
	"io"

	"github.com/protobom/protobom/pkg/sbom"
)

type Renderer interface {
	RenderNode(io.Writer, *sbom.Node, NodeGraphInfo) error
}

type NodeGraphInfo struct {
	Ancestor *sbom.Node
	Depth    int
	IsFirst  bool
	IsLast   bool
}
