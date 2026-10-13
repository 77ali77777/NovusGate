package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Server runtime code must log through log/slog, so every line is
// structured and filtered by LOG_LEVEL. CLI output for the user
// (cmd/control-plane commands other than serve) may keep fmt.

// mainGo holds both CLI commands and the server; only serverFuncs are runtime.
const mainGo = "../../../cmd/control-plane/main.go"

// serverFuncs are the server-runtime functions in cmd/control-plane/main.go.
var serverFuncs = map[string]bool{"runServer": true, "bootstrapSystem": true}

// alarm matches messages about errors, failures and warnings.
var alarm = regexp.MustCompile(`(?i)\b(error|failed|failure|warning)\b`)

// runtimeFiles returns every non-test Go file under internal/.
func runtimeFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found under internal/")
	}
	return files
}

// importNames maps a file's local package names for "fmt", "log", "log/slog"
// and "os" to their import paths, so aliases like stdlog "log" are caught.
func importNames(file *ast.File) map[string]string {
	names := map[string]string{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path != "fmt" && path != "log" && path != "log/slog" && path != "os" {
			continue
		}
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		names[local] = path
	}
	return names
}

// pkgCall returns the import path and function name of a call like pkg.Fn(...).
func pkgCall(names map[string]string, call *ast.CallExpr) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	path, ok := names[id.Name]
	return path, sel.Sel.Name, ok
}

// directPrints lists calls in n that bypass slog: fmt.Print*, log.Print*,
// log.Fatal*, log.Panic*, log.Default() and fmt.Fprint* to os.Stdout/Stderr.
func directPrints(fset *token.FileSet, file *ast.File, n ast.Node) []string {
	names := importNames(file)
	var bad []string
	ast.Inspect(n, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		path, fn, ok := pkgCall(names, call)
		if !ok {
			return true
		}
		forbidden := (path == "fmt" && strings.HasPrefix(fn, "Print")) ||
			(path == "log" && (strings.HasPrefix(fn, "Print") || strings.HasPrefix(fn, "Fatal") ||
				strings.HasPrefix(fn, "Panic") || fn == "Default"))
		if path == "fmt" && strings.HasPrefix(fn, "Fprint") && len(call.Args) > 0 {
			if w, ok := call.Args[0].(*ast.SelectorExpr); ok {
				if x, ok := w.X.(*ast.Ident); ok && names[x.Name] == "os" && (w.Sel.Name == "Stdout" || w.Sel.Name == "Stderr") {
					forbidden = true
				}
			}
		}
		if forbidden {
			bad = append(bad, fset.Position(call.Pos()).String()+": "+path+"."+fn)
		}
		return true
	})
	return bad
}

// quietAlarms lists slog.Info/Debug calls whose message is about an error,
// a failure or a warning: they would vanish at LOG_LEVEL=warn.
func quietAlarms(fset *token.FileSet, file *ast.File, n ast.Node) []string {
	names := importNames(file)
	var bad []string
	ast.Inspect(n, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		path, fn, ok := pkgCall(names, call)
		if !ok || path != "log/slog" || (fn != "Info" && fn != "Debug") {
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
	return bad
}

// scan applies inspect to every runtime file and to serverFuncs in main.go.
func scan(t *testing.T, inspect func(*token.FileSet, *ast.File, ast.Node) []string) []string {
	t.Helper()
	var bad []string
	for _, f := range runtimeFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		bad = append(bad, inspect(fset, file, file)...)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGo, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && serverFuncs[fn.Name.Name] {
			bad = append(bad, inspect(fset, file, fn)...)
		}
	}
	return bad
}

func TestRuntimeCodeLogsThroughSlog(t *testing.T) {
	if bad := scan(t, directPrints); len(bad) > 0 {
		t.Fatalf("runtime code must log through log/slog, found %d direct prints:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// TestLogLevelsMatchMessages catches a message about an error, a failure or a
// warning logged at Info or Debug: it would vanish at LOG_LEVEL=warn.
func TestLogLevelsMatchMessages(t *testing.T) {
	if bad := scan(t, quietAlarms); len(bad) > 0 {
		t.Fatalf("errors and warnings must be logged at Warn or Error:\n%s", strings.Join(bad, "\n"))
	}
}

func TestGuardCatchesAliasedImports(t *testing.T) {
	src := "package x\nimport stdlog \"log\"\nfunc f() { stdlog.Printf(\"x\") }\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bad := directPrints(fset, file, file); len(bad) != 1 {
		t.Fatalf("aliased log.Printf must be caught, got %v", bad)
	}
}
