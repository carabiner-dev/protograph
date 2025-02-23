package protograph

import (
	"io"
	"os"

	"github.com/carabiner-dev/protograph/render"
	"github.com/carabiner-dev/protograph/renderers/tty"
	"github.com/protobom/protobom/pkg/sbom"
)

// ProtoGraph is a library that renders protobom data to an io.Writer
// using a configurable renderer.
type ProtoGraph struct {
	nodeRenderer render.NodeRenderer
	Output       io.Writer
}

// New returns a new protograph object
func New() *ProtoGraph {
	return &ProtoGraph{
		nodeRenderer: tty.New(),
		Output:       os.Stdout,
	}
}

// GraphNodeList draws a NodeList using the configured Renderer
func (graph *ProtoGraph) GraphNodeList(nl *sbom.NodeList) error {
	for i, id := range nl.RootElements {

		err := graph.graphNodeAndRecurse(nl, nl.GetNodeByID(id), &map[string]struct{}{}, render.NodeGraphInfo{
			Ancestor:    nil,
			Descendants: nl.NodeDescendants(id, 1),
			Depth:       0,
			IsFirst:     i == 0,
			IsLast:      i == len(nl.RootElements)-1,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// graphNodeAndRecurse draws a node and recurses down to its descendants
func (graph *ProtoGraph) graphNodeAndRecurse(
	nl *sbom.NodeList,
	root *sbom.Node,
	seen *map[string]struct{},
	rootInfo render.NodeGraphInfo,
) error {
	// Get the node descendants using the protobom API
	rootInfo.Descendants = nl.NodeDescendants(root.Id, 1)

	if err := graph.nodeRenderer.RenderNode(graph.Output, root, rootInfo); err != nil {
		return err
	}
	if len(rootInfo.Descendants.Edges) == 0 {
		return nil
	}

	// Create a new node ID filtering out those we've already seen
	newlist := []string{}
	for _, id := range rootInfo.Descendants.Edges[0].To {
		// This circular refernce should not exist but ¯\_(ツ)_/¯
		if id == root.Id {
			continue
		}
		if _, ok := (*seen)[id]; ok {
			continue
		}
		newlist = append(newlist, id)
	}

	for i, id := range newlist {
		info := render.NodeGraphInfo{
			Ancestor: root,
			Depth:    rootInfo.Depth + 1,
			IsFirst:  i == 0,
			IsLast:   i == len(newlist)-1,
		}

		node := nl.GetNodeByID(id)

		// Add to the nodes we've seen
		(*seen)[id] = struct{}{}
		if err := graph.graphNodeAndRecurse(nl, node, seen, info); err != nil {
			return err
		}
	}
	return nil
}
