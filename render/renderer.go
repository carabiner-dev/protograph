package render

import (
	"github.com/carabiner-dev/protograph/options"
	"github.com/protobom/protobom/pkg/sbom"
)

type NodeListRender interface {
	RenderNodeList(options.Options, *sbom.NodeList) error
}

type NodeRenderer interface {
	RenderNode(options.Options, *sbom.Node, NodeGraphInfo) error
	DefaultOptions() any
}

type NodeGraphInfo struct {
	Ancestor    *sbom.Node
	Descendants *sbom.NodeList
	Depth       int
	IsFirst     bool
	IsLast      bool
}
