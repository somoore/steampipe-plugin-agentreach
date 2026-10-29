package agentreach

// Standards conformance checks for the Steampipe table, column, docs and
// coding standards:
//   https://steampipe.io/docs/develop/standards
//   https://steampipe.io/docs/develop/table-docs-standards
//   https://steampipe.io/docs/develop/coding-standards
//
// These run under `go test ./...` (and the pre-commit hook). They inspect the
// real *plugin.Plugin definition and the docs/ tree, so they fail if a new
// table or column drifts from the standards; no live database needed.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
)

// snakeCase matches lower snake_case identifiers (table and column names).
var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// standardColumns are ordered-last per the standards; used for ordering checks.
// akas/tags are listed for ordering robustness even though no table carries
// them: agentreach rows are local files and probes, not cloud resources.
var standardColumns = map[string]bool{
	"title": true,
	"akas":  true,
	"tags":  true,
}

func loadPlugin(t *testing.T) *plugin.Plugin {
	t.Helper()
	return Plugin(context.Background())
}

//// TABLE & COLUMN STANDARDS

func TestTableNaming(t *testing.T) {
	for name := range loadPlugin(t).TableMap {
		if !snakeCase.MatchString(name) {
			t.Errorf("table %q is not snake_case", name)
		}
		if !strings.HasPrefix(name, "agentreach_") {
			t.Errorf("table %q must be prefixed with the plugin name (agentreach_)", name)
		}
		// Singular: reject a trailing plural 's' on the last segment, allowing
		// known-singular exceptions that legitimately end in s.
		last := name[strings.LastIndex(name, "_")+1:]
		if strings.HasSuffix(last, "s") && !singularExceptions[last] {
			t.Errorf("table %q looks plural (segment %q); table names must be singular", name, last)
		}
	}
}

// singularExceptions are last-segment words that end in 's' but are singular.
var singularExceptions = map[string]bool{}

func TestColumnNaming(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		for _, c := range table.Columns {
			if !snakeCase.MatchString(c.Name) {
				t.Errorf("%s.%s is not snake_case", tableName, c.Name)
			}
		}
	}
}

func TestColumnDescriptions(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		if !wellFormedDescription(table.Description) {
			t.Errorf("table %s description must start capitalized and end with a period: %q", tableName, table.Description)
		}
		for _, c := range table.Columns {
			if strings.TrimSpace(c.Description) == "" {
				t.Errorf("%s.%s has no description", tableName, c.Name)
				continue
			}
			if !wellFormedDescription(c.Description) {
				t.Errorf("%s.%s description must start capitalized and end with a period: %q", tableName, c.Name, c.Description)
			}
		}
	}
}

func TestStandardColumnsPresent(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		names := columnNameSet(table)
		if _, ok := names["title"]; !ok {
			t.Errorf("table %s is missing the standard column 'title'", tableName)
		}
		if c := findColumn(table, "title"); c != nil && c.Type != proto.ColumnType_STRING {
			t.Errorf("%s.title must be ColumnType_STRING", tableName)
		}
	}
}

// TestColumnOrdering enforces key columns first, then the rest alphabetically,
// then standard columns last.
func TestColumnOrdering(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		keyNames := keyColumnNames(table)

		var got []string
		for _, c := range table.Columns {
			got = append(got, c.Name)
		}

		var keys, middle, std []string
		for _, n := range got {
			switch {
			case standardColumns[n]:
				std = append(std, n)
			case keyNames[n]:
				keys = append(keys, n)
			default:
				middle = append(middle, n)
			}
		}

		// Middle section must be alphabetical.
		if !sort.StringsAreSorted(middle) {
			sorted := append([]string(nil), middle...)
			sort.Strings(sorted)
			t.Errorf("table %s: non-key columns must be alphabetical.\n got: %v\nwant: %v", tableName, middle, sorted)
		}

		// Rebuild the expected order and compare positions: keys first (in key
		// order), then alphabetical middle, then standard last.
		want := append(append(append([]string(nil), keys...), middle...), std...)
		sort.Strings(want[len(keys) : len(keys)+len(middle)]) // sort only middle
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("table %s column order violates key->alpha->standard.\n got: %v\nwant: %v", tableName, got, want)
		}
	}
}

// rowTypes maps each table to the posture struct its list hydrate streams.
var rowTypes = map[string]reflect.Type{
	"agentreach_agent":            reflect.TypeOf(posture.Agent{}),
	"agentreach_project":          reflect.TypeOf(posture.Project{}),
	"agentreach_setting":          reflect.TypeOf(posture.Setting{}),
	"agentreach_hook":             reflect.TypeOf(posture.Hook{}),
	"agentreach_mcp_server":       reflect.TypeOf(posture.MCPServer{}),
	"agentreach_instruction_file": reflect.TypeOf(posture.InstructionFile{}),
	"agentreach_sandbox_rule":     reflect.TypeOf(posture.SandboxRule{}),
	"agentreach_reach_file":       reflect.TypeOf(posture.ReachFile{}),
	"agentreach_reach_host":       reflect.TypeOf(posture.ReachHost{}),
	"agentreach_plugin":           reflect.TypeOf(posture.Plugin{}),
	"agentreach_marketplace":      reflect.TypeOf(posture.Marketplace{}),
	"agentreach_leg":              reflect.TypeOf(posture.LegRow{}),
	"agentreach_path":             reflect.TypeOf(posture.Path{}),
	"agentreach_write_target":     reflect.TypeOf(posture.WriteTarget{}),
	"agentreach_environment":      reflect.TypeOf(posture.EnvControl{}),
	"agentreach_launch_flag":      reflect.TypeOf(posture.LaunchFlag{}),
	"agentreach_ci_workflow":      reflect.TypeOf(posture.CIWorkflow{}),
	"agentreach_sdk_launcher":     reflect.TypeOf(posture.SDKLauncher{}),
}

// fieldsWithoutColumns are struct fields deliberately not exposed as columns.
var fieldsWithoutColumns = map[string]bool{}

// TestEveryFieldHasColumn is the reverse of TestColumnsResolveToFields: a new
// field on a posture struct must reach SQL, or it is invisible to the mod.
// The column name is the field's json tag.
func TestEveryFieldHasColumn(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		rt := rowTypes[tableName]
		if rt == nil {
			continue
		}
		cols := map[string]bool{}
		for _, c := range table.Columns {
			cols[c.Name] = true
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" || fieldsWithoutColumns[tableName+"."+f.Name] {
				continue
			}
			if !cols[tag] {
				t.Errorf("%s: field %s (json %q) has no column", tableName, f.Name, tag)
			}
		}
	}
}

// camel converts snake_case to CamelCase the way the SDK's FromCamel does.
func camel(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// TestColumnsResolveToFields guards the FromCamel default transform: a column
// without an explicit Transform must map to an exported field on the row
// struct, or it silently returns null (which happened to four columns once).
func TestColumnsResolveToFields(t *testing.T) {
	for tableName, table := range loadPlugin(t).TableMap {
		rt, ok := rowTypes[tableName]
		if !ok {
			t.Errorf("table %s has no entry in rowTypes; add it", tableName)
			continue
		}
		for _, c := range table.Columns {
			if c.Transform != nil {
				continue
			}
			field := camel(c.Name)
			if _, ok := rt.FieldByName(field); !ok {
				t.Errorf("%s.%s has no explicit transform and %s has no field %q (FromCamel would return null)", tableName, c.Name, rt.Name(), field)
			}
		}
	}
}

//// DOCS STANDARDS

func TestEveryTableHasDoc(t *testing.T) {
	docsDir := repoPath(t, "docs", "tables")
	for tableName := range loadPlugin(t).TableMap {
		path := filepath.Join(docsDir, tableName+".md")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("table %s has no doc at docs/tables/%s.md", tableName, tableName)
		}
	}
}

func TestDocStructure(t *testing.T) {
	docsDir := repoPath(t, "docs", "tables")
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatalf("read docs/tables: %v", err)
	}
	h3 := regexp.MustCompile(`(?m)^### (.+)$`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(docsDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		content := string(body)
		table := strings.TrimSuffix(e.Name(), ".md")

		if !strings.HasPrefix(content, "# Table: "+table+"\n") {
			t.Errorf("%s: must start with '# Table: %s'", e.Name(), table)
		}
		if !strings.Contains(content, "\n## Examples\n") {
			t.Errorf("%s: missing '## Examples' section", e.Name())
		}

		headings := h3.FindAllStringSubmatch(content, -1)
		if len(headings) == 0 {
			t.Errorf("%s: has no ### example headings", e.Name())
			continue
		}
		// First example must be exactly "Basic info".
		if strings.TrimSpace(headings[0][1]) != "Basic info" {
			t.Errorf("%s: first example must be '### Basic info', got %q", e.Name(), headings[0][1])
		}
		if len(headings) < 2 {
			t.Errorf("%s: needs at least one example beyond Basic info", e.Name())
		}
		// Remaining descriptions: imperative mood: reject the documented
		// bad patterns (Listing..., List of...).
		for _, h := range headings[1:] {
			d := strings.TrimSpace(h[1])
			if strings.HasPrefix(d, "Listing ") {
				t.Errorf("%s: example %q should use 'List', not 'Listing'", e.Name(), d)
			}
			if regexp.MustCompile(`(?i)^list of `).MatchString(d) {
				t.Errorf("%s: example %q should not include 'of'", e.Name(), d)
			}
		}
	}
}

//// CODING STANDARDS

func TestPackageComment(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, repoPath(t, "agentreach", "plugin.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse plugin.go: %v", err)
	}
	if f.Doc == nil || strings.TrimSpace(f.Doc.Text()) == "" {
		t.Error("plugin.go must have a package comment (block comment before 'package agentreach')")
	}
}

// TestExportedDocComments checks every exported func/type in the package has a
// doc comment that starts with its own name, per the Go docs convention.
func TestExportedDocComments(t *testing.T) {
	dir := repoPath(t, "agentreach")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if !d.Name.IsExported() || d.Recv != nil {
						continue
					}
					checkDoc(t, d.Name.Name, d.Doc)
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						ts, ok := spec.(*ast.TypeSpec)
						if !ok || !ts.Name.IsExported() {
							continue
						}
						doc := ts.Doc
						if doc == nil {
							doc = d.Doc // single-spec block: comment sits on GenDecl
						}
						checkDoc(t, ts.Name.Name, doc)
					}
				}
			}
		}
	}
}

//// HELPERS

func wellFormedDescription(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if !strings.HasSuffix(s, ".") {
		return false
	}
	// "agentreach" is a deliberately lowercase project name; the standard's
	// capital-first-letter rule yields to it.
	if strings.HasPrefix(s, "agentreach") {
		return true
	}
	first := rune(s[0])
	return first >= 'A' && first <= 'Z'
}

func columnNameSet(table *plugin.Table) map[string]bool {
	set := map[string]bool{}
	for _, c := range table.Columns {
		set[c.Name] = true
	}
	return set
}

func findColumn(table *plugin.Table, name string) *plugin.Column {
	for _, c := range table.Columns {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func keyColumnNames(table *plugin.Table) map[string]bool {
	names := map[string]bool{}
	if table.List != nil {
		for _, k := range table.List.KeyColumns {
			names[k.Name] = true
		}
	}
	if table.Get != nil {
		for _, k := range table.Get.KeyColumns {
			names[k.Name] = true
		}
	}
	return names
}

func checkDoc(t *testing.T, name string, doc *ast.CommentGroup) {
	t.Helper()
	if doc == nil || strings.TrimSpace(doc.Text()) == "" {
		t.Errorf("exported %s has no doc comment", name)
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(doc.Text()), name) {
		t.Errorf("doc comment for %s should start with %q", name, name)
	}
}

// repoPath resolves a path relative to the repo root (this file lives in
// agentreach/, so the root is one level up).
func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return filepath.Join(append([]string{root}, parts...)...)
}
