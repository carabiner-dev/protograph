package protograph

import (
	"io"
	"os"
	"slices"

	"github.com/carabiner-dev/protograph/options"
	"github.com/carabiner-dev/protograph/render"
	"github.com/carabiner-dev/protograph/renderers/tty"
	"github.com/protobom/protobom/pkg/sbom"
)

// ProtoGraph is a library that renders protobom data to an io.Writer
// using a configurable renderer.
type ProtoGraph struct {
	Output       io.Writer
	nodeRenderer render.NodeRenderer
	Options      options.Options
}

// New returns a new protograph object
func New() *ProtoGraph {
	renderer := tty.New()

	// Initialize with the default options
	opts := options.Default
	// and the chosen renderer options
	opts.RendererOptions = renderer.DefaultOptions()

	return &ProtoGraph{
		nodeRenderer: renderer,
		Output:       os.Stdout,
		Options:      opts,
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

	if err := graph.nodeRenderer.RenderNode(graph.Options, root, rootInfo); err != nil {
		return err
	}
	if len(rootInfo.Descendants.Edges) == 0 {
		return nil
	}

	// Create a new node ID filtering out those we've already seen
	// and those types that options command not to render
	newlist := []string{}
	for _, id := range rootInfo.Descendants.Edges[0].To {
		// This circular refernce should not exist but ¯\_(ツ)_/¯
		if id == root.Id {
			continue
		}
		if _, ok := (*seen)[id]; ok {
			continue
		}

		// Any ID in the edges not found on the graph we skip
		node := nl.GetNodeByID(id)
		if node == nil {
			continue
		}

		if node.GetType() == sbom.Node_FILE && !graph.Options.RenderFiles {
			continue
		} else if node.GetType() == sbom.Node_PACKAGE && !graph.Options.RenderPackages {
			continue
		}

		newlist = append(newlist, id)
	}

	if graph.Options.SortPackagesFiles {
		slices.SortFunc(newlist, func(a, b string) int {
			nodeA := nl.GetNodeByID(a)
			nodeB := nl.GetNodeByID(b)

			switch {
			case nodeA.GetType() == nodeB.GetType():
				return 0
			case nodeA.GetType() == sbom.Node_PACKAGE:
				return -1
			case nodeB.GetType() == sbom.Node_PACKAGE:
				return 1
			default:
				return 0
			}
		})
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
