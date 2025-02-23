package render

import (
	"io"

	"github.com/protobom/protobom/pkg/sbom"
)

type NodeListRender interface {
	RenderNodeList(io.Writer, *sbom.NodeList) error
}

type NodeRenderer interface {
	RenderNode(io.Writer, *sbom.Node, NodeGraphInfo) error
}

type NodeGraphInfo struct {
	Ancestor    *sbom.Node
	Descendants *sbom.NodeList
	Depth       int
	IsFirst     bool
	IsLast      bool
}
