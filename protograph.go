package protograph

import (
	"io"
	"os"
	"slices"
	"strings"

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

// SetRenderer swaps the NodeRenderer used to draw the graph. It also resets
// the renderer-specific options (Options.RendererOptions) to the new renderer's
// defaults so the graph is immediately usable with the injected renderer.
// Callers that need custom renderer options should set Options.RendererOptions
// after calling SetRenderer.
func (graph *ProtoGraph) SetRenderer(r render.NodeRenderer) {
	graph.nodeRenderer = r
	graph.Options.RendererOptions = r.DefaultOptions()
}

// GraphNodeList draws a NodeList using the configured Renderer
func (graph *ProtoGraph) GraphNodeList(nl *sbom.NodeList) error {
	// Global map to track nodes that have had their children rendered (used when FullTree is false)
	rendered := make(map[string]struct{})

	for i, id := range nl.RootElements {
		// Start with ancestors containing the root node to prevent cycles back to it
		ancestors := map[string]struct{}{id: {}}
		err := graph.graphNodeAndRecurse(nl, nl.GetNodeByID(id), ancestors, rendered, render.NodeGraphInfo{
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
// ancestors: tracks nodes in the current path (for cycle prevention, per-branch)
// rendered: tracks nodes whose children have been rendered (global, used when FullTree is false)
func (graph *ProtoGraph) graphNodeAndRecurse(
	nl *sbom.NodeList,
	root *sbom.Node,
	ancestors map[string]struct{},
	rendered map[string]struct{},
	rootInfo render.NodeGraphInfo,
) error {
	// Get the node descendants using the protobom API
	rootInfo.Descendants = nl.NodeDescendants(root.Id, 1)

	// Check if this node has children that will be skipped (already rendered elsewhere)
	hasChildren := len(rootInfo.Descendants.Edges) > 0 && len(rootInfo.Descendants.Edges[0].To) > 0
	skipChildren := false
	if !graph.Options.FullTree && hasChildren {
		if _, alreadyRendered := rendered[root.Id]; alreadyRendered {
			skipChildren = true
			rootInfo.ChildrenSkipped = true
		}
	}

	if err := graph.nodeRenderer.RenderNode(graph.Options, root, rootInfo); err != nil {
		return err
	}
	if !hasChildren {
		return nil
	}

	// When FullTree is false, skip children if this node has already been rendered with children
	if skipChildren {
		return nil
	}
	if !graph.Options.FullTree {
		// Mark this node as having its children rendered
		rendered[root.Id] = struct{}{}
	}

	// Collect the children to walk, filtering out ancestors (to prevent
	// cycles) and those types that options command not to render
	children := []*sbom.Node{}
	for _, id := range rootInfo.Descendants.Edges[0].To {
		// Skip circular references to self
		if id == root.Id {
			continue
		}
		// Skip if this node is an ancestor (would create a cycle)
		if _, isAncestor := ancestors[id]; isAncestor {
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

		children = append(children, node)
	}

	// Walk the children in a fixed order. protobom gathers a node's
	// descendants through a map, so they arrive in a different order on
	// every call; walked as they come, the same document would be drawn
	// differently each time, and a node reached through several parents
	// would be expanded under a different one (it is expanded where it is
	// first met). Ordering them makes a graph draw the same way every time.
	slices.SortFunc(children, func(a, b *sbom.Node) int {
		return compareNodes(a, b, graph.Options.SortPackagesFiles)
	})

	for i, node := range children {
		info := render.NodeGraphInfo{
			Ancestor: root,
			Depth:    rootInfo.Depth + 1,
			IsFirst:  i == 0,
			IsLast:   i == len(children)-1,
		}

		// Create a new ancestors map for this branch including the current node
		// This allows nodes to appear in multiple branches while preventing cycles
		childAncestors := make(map[string]struct{}, len(ancestors)+1)
		for k := range ancestors {
			childAncestors[k] = struct{}{}
		}
		childAncestors[node.Id] = struct{}{}

		if err := graph.graphNodeAndRecurse(nl, node, childAncestors, rendered, info); err != nil {
			return err
		}
	}
	return nil
}

// compareNodes orders two sibling nodes: by name without regard to case,
// then by version, then by id, which no two nodes share, so the order is
// total and the same on every run. With packagesFirst, packages come before
// files whatever their names.
func compareNodes(a, b *sbom.Node, packagesFirst bool) int {
	if packagesFirst && a.GetType() != b.GetType() {
		if a.GetType() == sbom.Node_PACKAGE {
			return -1
		}
		if b.GetType() == sbom.Node_PACKAGE {
			return 1
		}
	}
	if c := strings.Compare(strings.ToLower(a.GetName()), strings.ToLower(b.GetName())); c != 0 {
		return c
	}
	if c := strings.Compare(a.GetName(), b.GetName()); c != 0 {
		return c
	}
	if c := strings.Compare(a.GetVersion(), b.GetVersion()); c != 0 {
		return c
	}
	return strings.Compare(a.GetId(), b.GetId())
}
