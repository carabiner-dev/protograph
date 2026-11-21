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
	// Who hangs under whom, with every edge read the right way round.
	children := childIndex(nl)

	for i, id := range nl.RootElements {
		// Start with ancestors containing the root node to prevent cycles back to it
		ancestors := map[string]struct{}{id: {}}
		err := graph.graphNodeAndRecurse(nl, nl.GetNodeByID(id), children, ancestors, rendered, render.NodeGraphInfo{
			Ancestor: nil,
			Depth:    0,
			IsFirst:  i == 0,
			IsLast:   i == len(nl.RootElements)-1,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// childIndex maps every node id to the ids of its children in the tree: the
// destinations of its forward edges, plus the sources of the inverse edges
// that point at it.
//
// protobom keeps the relationship names and directions of SPDX 2, which
// states many of them from the owned node: "A DEPENDENCY_OF B", "A
// CONTAINED_BY B" and "A BUILD_TOOL_OF B" all name the owner last. Followed
// from source to destination, as any other edge, those would hang the owner
// under what it owns, or leave a dependency out of the tree for want of an
// edge leading to it. sbom.Edge_Type.Inverse says which types they are.
//
// A child is listed once under a parent, however many edges relate the two.
func childIndex(nl *sbom.NodeList) map[string][]string {
	children := map[string][]string{}
	seen := map[[2]string]struct{}{}
	add := func(parent, child string) {
		pair := [2]string{parent, child}
		if _, dup := seen[pair]; dup {
			return
		}
		seen[pair] = struct{}{}
		children[parent] = append(children[parent], child)
	}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			if e.GetType().Inverse() {
				add(to, e.GetFrom())
			} else {
				add(e.GetFrom(), to)
			}
		}
	}
	return children
}

// descendants builds the NodeList handed to renderers as
// NodeGraphInfo.Descendants: the node and its children in the tree, joined
// by a single ancestor edge. It is the shape of protobom's
// NodeList.NodeDescendants(id, 1), which the walk used to hand over.
func descendants(nl *sbom.NodeList, node *sbom.Node, childIDs []string) *sbom.NodeList {
	desc := &sbom.NodeList{
		Nodes:        []*sbom.Node{node},
		Edges:        []*sbom.Edge{},
		RootElements: []string{node.GetId()},
	}
	edge := &sbom.Edge{Type: sbom.Edge_ancestor, From: node.GetId(), To: []string{}}
	for _, id := range childIDs {
		// A node is not its own descendant, and an edge may name a node
		// the document does not have.
		child := nl.GetNodeByID(id)
		if child == nil || id == node.GetId() {
			continue
		}
		desc.Nodes = append(desc.Nodes, child)
		edge.To = append(edge.To, id)
	}
	if len(edge.To) > 0 {
		desc.Edges = append(desc.Edges, edge)
	}
	return desc
}

// graphNodeAndRecurse draws a node and recurses down to its descendants
// children: who hangs under whom in the tree (see childIndex)
// ancestors: tracks nodes in the current path (for cycle prevention, per-branch)
// rendered: tracks nodes whose children have been rendered (global, used when FullTree is false)
func (graph *ProtoGraph) graphNodeAndRecurse(
	nl *sbom.NodeList,
	root *sbom.Node,
	children map[string][]string,
	ancestors map[string]struct{},
	rendered map[string]struct{},
	rootInfo render.NodeGraphInfo,
) error {
	rootInfo.Descendants = descendants(nl, root, children[root.Id])

	// Check if this node has children that will be skipped (already rendered elsewhere)
	hasChildren := len(rootInfo.Descendants.Edges) > 0
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
	toWalk := []*sbom.Node{}
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

		toWalk = append(toWalk, node)
	}

	// Walk the children in a fixed order, whatever order the document
	// states its edges in: a graph draws the same way every time, and a
	// node reached through several parents (it is expanded where it is
	// first met) is always expanded under the same one.
	slices.SortFunc(toWalk, func(a, b *sbom.Node) int {
		return compareNodes(a, b, graph.Options.SortPackagesFiles)
	})

	for i, node := range toWalk {
		info := render.NodeGraphInfo{
			Ancestor: root,
			Depth:    rootInfo.Depth + 1,
			IsFirst:  i == 0,
			IsLast:   i == len(toWalk)-1,
		}

		// Create a new ancestors map for this branch including the current node
		// This allows nodes to appear in multiple branches while preventing cycles
		childAncestors := make(map[string]struct{}, len(ancestors)+1)
		for k := range ancestors {
			childAncestors[k] = struct{}{}
		}
		childAncestors[node.Id] = struct{}{}

		if err := graph.graphNodeAndRecurse(nl, node, children, childAncestors, rendered, info); err != nil {
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
