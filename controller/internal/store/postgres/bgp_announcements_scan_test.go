package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// bgpAnnouncementColumnList expands bgpAnnouncementCols into its individual
// column expressions, unwrapping COALESCE(...) wrappers.
func bgpAnnouncementColumnList() []string {
	cols := regexp.MustCompile(`COALESCE\([^)]*\)`).ReplaceAllString(bgpAnnouncementCols, "coalesced")
	var out []string
	for _, part := range strings.Split(cols, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// bgpAnnouncementScanCalls returns the Scan calls inside the named method.
func bgpAnnouncementScanCalls(t *testing.T, f *ast.File, method string) []*ast.CallExpr {
	t.Helper()
	var calls []*ast.CallExpr
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != method {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Scan" {
				calls = append(calls, call)
			}
			return true
		})
	}
	if len(calls) == 0 {
		t.Fatalf("no Scan call found in %s", method)
	}
	return calls
}

// bgpAnnouncementHelperTargets counts the elements of the []any literal
// returned by the named helper.
func bgpAnnouncementHelperTargets(t *testing.T, f *ast.File, name string) int {
	t.Helper()
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		count := -1
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			arr, ok := cl.Type.(*ast.ArrayType)
			if !ok {
				return true
			}
			switch elt := arr.Elt.(type) {
			case *ast.Ident:
				if elt.Name != "any" {
					return true
				}
			case *ast.InterfaceType:
			default:
				return true
			}
			count = len(cl.Elts)
			return false
		})
		if count < 0 {
			t.Fatalf("%s does not return an []any literal", name)
		}
		return count
	}
	t.Fatalf("helper %s not found", name)
	return 0
}

// bgpAnnouncementScanDestinations counts the destinations a scan uses,
// resolving the shared bgpAnnouncementScanTargets helper when the scan
// delegates to it.
func bgpAnnouncementScanDestinations(t *testing.T, f *ast.File, scan *ast.CallExpr) int {
	t.Helper()
	if len(scan.Args) == 1 {
		if call, ok := scan.Args[0].(*ast.CallExpr); ok {
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if name == "bgpAnnouncementScanTargets" {
				return bgpAnnouncementHelperTargets(t, f, "bgpAnnouncementScanTargets")
			}
		}
	}
	return len(scan.Args)
}

// TestBGPAnnouncementListScansEveryColumn guards the announcement recovery
// path: pgx rejects a scan whose destination count differs from the selected
// column count, which would make every ListActive/ListByStatus/ListDismissed
// call fail at runtime and hide kind/rule_spec from the recovery code.
func TestBGPAnnouncementListScansEveryColumn(t *testing.T) {
	cols := bgpAnnouncementColumnList()
	f, err := parser.ParseFile(token.NewFileSet(), "bgp_announcements.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"scanOne", "list"} {
		for _, scan := range bgpAnnouncementScanCalls(t, f, method) {
			if got := bgpAnnouncementScanDestinations(t, f, scan); got != len(cols) {
				t.Errorf("%s scans %d destinations for %d columns; pgx rejects the mismatch", method, got, len(cols))
			}
		}
	}
}

// TestBGPAnnouncementScanCountMatchesColumns keeps the column list and the
// shared scan destinations in lockstep.
func TestBGPAnnouncementScanCountMatchesColumns(t *testing.T) {
	cols := bgpAnnouncementColumnList()
	if len(cols) != bgpAnnouncementScanCount {
		t.Errorf("bgpAnnouncementCols selects %d columns, scan count const=%d", len(cols), bgpAnnouncementScanCount)
	}
	if got := len(bgpAnnouncementScanTargets(&store.BGPAnnouncement{})); got != bgpAnnouncementScanCount {
		t.Errorf("scan targets=%d, scan count const=%d", got, bgpAnnouncementScanCount)
	}
}
