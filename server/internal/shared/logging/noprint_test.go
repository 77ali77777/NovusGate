package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runtimeDirs hold server runtime code: it must log through slog so every
// line is structured and filtered by LOG_LEVEL. CLI output for the user
// (cmd/control-plane commands other than serve) may keep fmt.
var runtimeDirs = []string{
	"../../controlplane/api/rest",
	"../../controlplane/firewall",
	"../../controlplane/store",
	"../../netctl/nft",
	"../../wireguard",
}

// serverFuncs are the server-runtime functions in cmd/control-plane/main.go.
var serverFuncs = map[string]bool{"runServer": true, "bootstrapSystem": true}

func TestRuntimeCodeLogsThroughSlog(t *testing.T) {
	var bad []string
	check := func(fset *token.FileSet, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			forbidden := (pkg.Name == "log" && (strings.HasPrefix(name, "Print") || strings.HasPrefix(name, "Fatal"))) ||
				(pkg.Name == "fmt" && strings.HasPrefix(name, "Print"))
			if pkg.Name == "fmt" && strings.HasPrefix(name, "Fprint") && len(call.Args) > 0 {
				if w, ok := call.Args[0].(*ast.SelectorExpr); ok {
					if x, ok := w.X.(*ast.Ident); ok && x.Name == "os" && (w.Sel.Name == "Stdout" || w.Sel.Name == "Stderr") {
						forbidden = true
					}
				}
			}
			if forbidden {
				bad = append(bad, fset.Position(call.Pos()).String()+": "+pkg.Name+"."+name)
			}
			return true
		})
	}
	for _, dir := range runtimeDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files in %s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			check(fset, file)
		}
	}
	mainGo := "../../../cmd/control-plane/main.go"
	if _, err := os.Stat(mainGo); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGo, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && serverFuncs[fn.Name.Name] {
			check(fset, fn)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("runtime code must log through log/slog, found %d direct prints:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// TestLogLevelsMatchMessages catches a message about an error, a failure or a
// warning logged at Info or Debug: it would vanish at LOG_LEVEL=warn.
func TestLogLevelsMatchMessages(t *testing.T) {
	alarm := regexp.MustCompile(`(?i)\b(error|failed|failure|warning)\b`)
	var bad []string
	check := func(fset *token.FileSet, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "slog" || (sel.Sel.Name != "Info" && sel.Sel.Name != "Debug") {
				return true
			}
			msg := call.Args[0]
			if inner, ok := msg.(*ast.CallExpr); ok && len(inner.Args) > 0 {
				msg = inner.Args[0] // slog.Info(fmt.Sprintf("...", ...))
			}
			if lit, ok := msg.(*ast.BasicLit); ok && alarm.MatchString(lit.Value) {
				bad = append(bad, fset.Position(call.Pos()).String()+": "+lit.Value)
			}
			return true
		})
	}
	for _, dir := range runtimeDirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			check(fset, file)
		}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../../../cmd/control-plane/main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && serverFuncs[fn.Name.Name] {
			check(fset, fn)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("errors and warnings must be logged at Warn or Error:\n%s", strings.Join(bad, "\n"))
	}
}
