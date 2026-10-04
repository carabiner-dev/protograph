// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protograph

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/carabiner-dev/protograph/options"
	"github.com/carabiner-dev/protograph/render"
)

// recorder is a renderer that writes down the walk: one line per node, in
// the order rendered, indented by depth, with what the graph said about it.
type recorder struct {
	lines []string
}

func (r *recorder) DefaultOptions() any { return nil }

func (r *recorder) RenderNode(_ options.Options, n *sbom.Node, info render.NodeGraphInfo) error {
	line := strings.Repeat("  ", info.Depth) + n.GetId()
	if info.ChildrenSkipped {
		line += " (repeated)"
	}
	if info.IsFirst {
		line += " first"
	}
	if info.IsLast {
		line += " last"
	}
	r.lines = append(r.lines, line)
	return nil
}

// walk renders a node list and answers the recorded lines.
func walk(t *testing.T, nl *sbom.NodeList, configure func(*options.Options)) string {
	t.Helper()
	rec := &recorder{}
	g := New()
	g.SetRenderer(rec)
	if configure != nil {
		configure(&g.Options)
	}
	if err := g.GraphNodeList(nl); err != nil {
		t.Fatal(err)
	}
	return strings.Join(rec.lines, "\n") + "\n"
}

func pkg(id, name, version string) *sbom.Node {
	return &sbom.Node{Id: id, Name: name, Version: version, Type: sbom.Node_PACKAGE}
}

func file(id, name string) *sbom.Node {
	return &sbom.Node{Id: id, Name: name, Type: sbom.Node_FILE}
}

// graphOf builds a node list rooted at the first node, with one edge per
// "from to" pair.
func graphOf(nodes []*sbom.Node, edges ...string) *sbom.NodeList {
	nl := sbom.NewNodeList()
	files := map[string]bool{}
	for _, n := range nodes {
		nl.AddNode(n)
		files[n.GetId()] = n.GetType() == sbom.Node_FILE
	}
	nl.RootElements = []string{nodes[0].GetId()}
	for _, e := range edges {
		from, to, _ := strings.Cut(e, " ")
		kind := sbom.Edge_dependsOn
		if files[to] {
			kind = sbom.Edge_contains
		}
		nl.AddEdge(&sbom.Edge{Type: kind, From: from, To: []string{to}})
	}
	return nl
}

// Siblings are walked by name, then version, then id, and a graph is walked
// the same way every time. protobom hands the children over in map order,
// which changes from call to call.
func TestChildrenAreWalkedInAFixedOrder(t *testing.T) {
	nodes := []*sbom.Node{pkg("root", "app", "1.0.0")}
	var edges []string
	// Enough children that a random order would show at once, added in an
	// order that is not the sorted one.
	for _, name := range []string{"mango", "Apple", "zebra", "banana", "apple", "cherry", "Banana", "kiwi", "fig", "date"} {
		id := "id-" + name
		nodes = append(nodes, pkg(id, name, "1.0.0"))
		edges = append(edges, "root "+id)
	}
	nl := graphOf(nodes, edges...)

	want := strings.Join([]string{
		"root first last",
		// Case does not separate names; between two that differ only by
		// case, the capital comes first.
		"  id-Apple first",
		"  id-apple",
		"  id-Banana",
		"  id-banana",
		"  id-cherry",
		"  id-date",
		"  id-fig",
		"  id-kiwi",
		"  id-mango",
		"  id-zebra last",
	}, "\n") + "\n"

	for i := range 50 {
		if got := walk(t, nl, nil); got != want {
			t.Fatalf("walk %d:\n%s\nwant:\n%s", i+1, got, want)
		}
	}
}

func TestSameNameIsOrderedByVersionThenID(t *testing.T) {
	nl := graphOf(
		[]*sbom.Node{
			pkg("root", "app", ""),
			pkg("c", "lib", "2.0.0"), pkg("b", "lib", "1.0.0"), pkg("z", "lib", "1.0.0"), pkg("a", "lib", "10.0.0"),
		},
		"root c", "root b", "root z", "root a",
	)
	// Versions compare as text: this is an order to walk in, not a claim
	// about which release is newer.
	want := "root first last\n  b first\n  z\n  a\n  c last\n"
	for range 20 {
		if got := walk(t, nl, nil); got != want {
			t.Fatalf("walk:\n%s\nwant:\n%s", got, want)
		}
	}
}

func TestPackagesBeforeFilesIsAnOption(t *testing.T) {
	nl := graphOf(
		[]*sbom.Node{pkg("root", "app", ""), pkg("p-zlib", "zlib", ""), file("f-a", "a.txt"), pkg("p-curl", "curl", ""), file("f-m", "main.go")},
		"root p-zlib", "root f-a", "root p-curl", "root f-m",
	)

	// The default: packages first, each kind by name.
	if got, want := walk(t, nl, nil), "root first last\n  p-curl first\n  p-zlib\n  f-a\n  f-m last\n"; got != want {
		t.Errorf("packages first:\n%s\nwant:\n%s", got, want)
	}
	// Without it, one list by name.
	mixed := walk(t, nl, func(o *options.Options) { o.SortPackagesFiles = false })
	if want := "root first last\n  f-a first\n  p-curl\n  f-m\n  p-zlib last\n"; mixed != want {
		t.Errorf("mixed:\n%s\nwant:\n%s", mixed, want)
	}
	// Files left out: the packages are first and last among themselves.
	noFiles := walk(t, nl, func(o *options.Options) { o.RenderFiles = false })
	if want := "root first last\n  p-curl first\n  p-zlib last\n"; noFiles != want {
		t.Errorf("without files:\n%s\nwant:\n%s", noFiles, want)
	}
}

// A node reached through several parents is expanded where it is first met
// and marked as repeated after that. With a fixed order, "first" is always
// the same parent.
func TestASharedNodeIsExpandedUnderTheSameParentEveryTime(t *testing.T) {
	nl := graphOf(
		[]*sbom.Node{
			pkg("root", "app", ""), pkg("b", "beta", ""), pkg("a", "alpha", ""), pkg("g", "gamma", ""),
			pkg("shared", "shared", ""), pkg("leaf", "leaf", ""),
		},
		"root b", "root a", "root g", "a shared", "b shared", "g shared", "shared leaf",
	)
	want := strings.Join([]string{
		"root first last",
		"  a first",
		"    shared first last",
		"      leaf first last",
		"  b",
		"    shared (repeated) first last",
		"  g last",
		"    shared (repeated) first last",
	}, "\n") + "\n"
	for i := range 50 {
		if got := walk(t, nl, nil); got != want {
			t.Fatalf("walk %d:\n%s\nwant:\n%s", i+1, got, want)
		}
	}

	// With the full tree asked for, it is expanded everywhere.
	full := walk(t, nl, func(o *options.Options) { o.FullTree = true })
	if strings.Contains(full, "(repeated)") || strings.Count(full, "leaf") != 3 {
		t.Errorf("full tree:\n%s", full)
	}
}

func TestCyclesAreCut(t *testing.T) {
	nl := graphOf(
		[]*sbom.Node{pkg("root", "app", ""), pkg("a", "alpha", ""), pkg("b", "beta", "")},
		"root a", "a b", "b a", "b root", "a a",
	)
	if got, want := walk(t, nl, nil), "root first last\n  a first last\n    b first last\n"; got != want {
		t.Errorf("walk:\n%s\nwant:\n%s", got, want)
	}
}

// The comparison is a total order: no two different nodes compare equal, and
// it does not depend on the order it is asked in.
func TestCompareNodes(t *testing.T) {
	nodes := []*sbom.Node{
		pkg("1", "b", "1"), pkg("2", "a", "2"), pkg("3", "a", "1"), pkg("4", "a", "1"),
		file("5", "a"), file("6", "A"), pkg("7", "", ""), pkg("8", "", ""),
	}
	for _, packagesFirst := range []bool{true, false} {
		for i, a := range nodes {
			for j, b := range nodes {
				ab, ba := compareNodes(a, b, packagesFirst), compareNodes(b, a, packagesFirst)
				if (i == j) != (ab == 0) {
					t.Errorf("packagesFirst=%v: compare(%s, %s) = %d", packagesFirst, a.Id, b.Id, ab)
				}
				if ab != -ba {
					t.Errorf("packagesFirst=%v: compare(%s, %s) = %d but the reverse is %d", packagesFirst, a.Id, b.Id, ab, ba)
				}
			}
		}
		// Sorting any arrangement gives the same list.
		var first string
		for shift := range len(nodes) {
			arranged := append(slices.Clone(nodes[shift:]), nodes[:shift]...)
			slices.SortFunc(arranged, func(a, b *sbom.Node) int { return compareNodes(a, b, packagesFirst) })
			ids := fmt.Sprint(func() (out []string) {
				for _, n := range arranged {
					out = append(out, n.Id)
				}
				return out
			}())
			if shift == 0 {
				first = ids
			} else if ids != first {
				t.Errorf("packagesFirst=%v: sorted %s from one arrangement, %s from another", packagesFirst, first, ids)
			}
		}
	}
}
