package all

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The guard keeps every byte a module sends inside the safety layer. It
// parses every non-test Go file under client/modules and fails if a module
// could open a socket, resolve a name or run code the safety layer does
// not see: forbidden imports, references to dialers, listeners, resolvers
// and default HTTP clients, transports that dial on their own, linkname
// tricks and non-Go sources such as assembly.

// stdBans are standard-library packages modules may not import.
var stdBans = []string{
	"C",
	"syscall",
	"unsafe",
	"os/exec",
	"plugin",
	"runtime/cgo",
	"log/syslog",
	"net/smtp",
	"net/rpc",
	"net/http/httptest",
	"net/http/httputil",
	"net/http/cgi",
	"net/http/fcgi",
	"net/http/pprof",
}

// dependencyAllowlist is every non-standard import path, or path prefix, a
// module may use. golang.org/x/sys, golang.org/x/net/icmp, ipv4, ipv6 and
// every other dependency are refused because they are not listed.
var dependencyAllowlist = []string{
	"google.golang.org/protobuf",
	"github.com/hopbits/client/gen",
	"github.com/hopbits/client/module",
	"github.com/hopbits/client/modules",
	"github.com/hopbits/client/protocol",
	"golang.org/x/net/publicsuffix",
	"golang.org/x/net/dns/dnsmessage",
}

// refBans are identifiers modules may not reference, by import path. A
// trailing * matches any name with that prefix.
var refBans = map[string][]string{
	"net": {"Dial*", "Listen*", "Lookup*", "DefaultResolver", "Resolver", "Dialer", "File*", "Interface*"},
	"net/http": {"Get", "Post", "PostForm", "Head", "DefaultClient", "DefaultTransport", "Client", "Server",
		"ProxyFromEnvironment", "ProxyURL", "NewFileTransport*", "ListenAndServe*", "Serve*"},
	"crypto/tls":    {"Dial*", "Listen", "NewListener"},
	"net/textproto": {"Dial"},
	"os":            {"StartProcess", "NewFile"},
}

// transportBans are http.Transport fields that would let a transport dial
// or proxy on its own.
var transportBans = []string{"Dial", "DialTLS", "DialTLSContext", "Proxy", "GetProxyConnectHeader", "OnProxyConnectResponse", "ProxyConnectHeader"}

// foreignSources are files the go tool compiles or links that the guard
// cannot read.
var foreignSources = []string{".s", ".S", ".sx", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".f", ".F", ".for", ".f90", ".syso", ".swig", ".swigcxx"}

func importBan(path string) string {
	first, _, _ := strings.Cut(path, "/")
	if !strings.Contains(first, ".") {
		for _, b := range stdBans {
			if path == b || strings.HasPrefix(path, b+"/") {
				return "reaches the network or the OS without the safety layer"
			}
		}
		return ""
	}
	for _, a := range dependencyAllowlist {
		if path == a || strings.HasPrefix(path, a+"/") {
			return ""
		}
	}
	return "is not on the modules' dependency allowlist"
}

func refBanned(path, name string) bool {
	for _, p := range refBans[path] {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == p {
			return true
		}
	}
	return false
}

func transportBan(lit *ast.CompositeLit) string {
	keys := map[string]ast.Expr{}
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			return "uses unkeyed fields"
		}
		if k, ok := kv.Key.(*ast.Ident); ok {
			keys[k.Name] = kv.Value
		}
	}
	dial, ok := keys["DialContext"]
	if !ok {
		return "does not set DialContext, so it would dial on its own"
	}
	if id, ok := dial.(*ast.Ident); ok && id.Name == "nil" {
		return "sets DialContext to nil"
	}
	for _, k := range transportBans {
		if _, ok := keys[k]; ok {
			return "sets " + k
		}
	}
	return ""
}

// defaultName is the name an import gets without an explicit one, for the
// standard-library paths the guard looks up.
func defaultName(path string) string {
	return path[strings.LastIndex(path, "/")+1:]
}

// checkFile returns the guard's findings for one parsed file.
func checkFile(fset *token.FileSet, f *ast.File) []string {
	var out []string
	report := func(n ast.Node, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
	}

	local := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			report(imp, "unreadable import %s", imp.Path.Value)
			continue
		}
		if why := importBan(path); why != "" {
			report(imp, "import %q %s", path, why)
		}
		name := defaultName(path)
		if imp.Name != nil {
			switch imp.Name.Name {
			case ".":
				report(imp, "dot import of %q hides what it references", path)
				continue
			case "_":
				continue
			default:
				name = imp.Name.Name
			}
		}
		local[name] = path
	}

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") || strings.HasPrefix(c.Text, "//go:cgo_") {
				report(c, "compiler directive %q", strings.Fields(c.Text)[0])
			}
		}
	}

	// http.Transport may appear only as the type of a literal that sets
	// DialContext, so that it dials through the safety layer.
	literalTypes := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && isRef(sel, local, "net/http", "Transport") {
				literalTypes[sel] = true
				if why := transportBan(n); why != "" {
					report(n, "http.Transport literal %s", why)
				}
			}
		case *ast.SelectorExpr:
			id, ok := n.X.(*ast.Ident)
			if !ok {
				return true
			}
			path, ok := local[id.Name]
			if !ok {
				return true
			}
			if path == "net/http" && n.Sel.Name == "Transport" {
				if !literalTypes[n] {
					report(n, "http.Transport used outside a literal that sets DialContext")
				}
				return true
			}
			if refBanned(path, n.Sel.Name) {
				report(n, "reference to %s.%s bypasses the safety layer", path, n.Sel.Name)
			}
		}
		return true
	})
	return out
}

func isRef(sel *ast.SelectorExpr, local map[string]string, path, name string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && local[id.Name] == path && sel.Sel.Name == name
}

// checkTree runs the guard over every non-test Go file under root and
// counts the files it read per directory.
func checkTree(root string) (problems []string, files map[string]int, err error) {
	files = map[string]int{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		if slices.Contains(foreignSources, ext) {
			problems = append(problems, path+": non-Go source the guard cannot check")
			return nil
		}
		if ext != ".go" || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		problems = append(problems, checkFile(fset, f)...)
		files[filepath.Base(filepath.Dir(path))]++
		return nil
	})
	return problems, files, err
}

func TestModulesStayInsideTheSafetyLayer(t *testing.T) {
	problems, files, err := checkTree("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	for _, dir := range []string{"httpcheck", "tcpconnect", "icmpping", "dnsquery", "traceroute", "mtr", "kit"} {
		if files[dir] == 0 {
			t.Errorf("guard read no files in %s; files read: %v", dir, files)
		}
	}
}

func TestGuardCatchesBypasses(t *testing.T) {
	bad := map[string]string{
		"syscall":               `import "syscall"; var _ = syscall.Socket`,
		"unsafe":                `import _ "unsafe"`,
		"os/exec":               `import "os/exec"; var _ = exec.Command`,
		"cgo":                   `import "C"`,
		"x/sys":                 `import "golang.org/x/sys/unix"; var _ = unix.Socket`,
		"x/net/icmp":            `import "golang.org/x/net/icmp"; var _ = icmp.ListenPacket`,
		"x/net/ipv4":            `import "golang.org/x/net/ipv4"; var _ = ipv4.NewConn`,
		"x/net/ipv6":            `import "golang.org/x/net/ipv6"; var _ = ipv6.NewConn`,
		"x/net/proxy":           `import "golang.org/x/net/proxy"; var _ = proxy.Direct`,
		"websocket":             `import "github.com/coder/websocket"; var _ = websocket.Dial`,
		"safety internals":      `import "github.com/hopbits/client/safety"; var _ = safety.Denied`,
		"net.Dial":              `import "net"; var _, _ = net.Dial("tcp", "192.0.2.1:80")`,
		"net.DialTimeout":       `import "net"; var _ = net.DialTimeout`,
		"renamed net":           `import n "net"; var _ = n.DialTCP`,
		"net.Listen":            `import "net"; var _ = net.Listen`,
		"net.ListenPacket":      `import "net"; var _ = net.ListenPacket`,
		"net.LookupHost":        `import "net"; var _ = net.LookupHost`,
		"net.DefaultResolver":   `import "net"; var _ = net.DefaultResolver`,
		"net.Resolver":          `import "net"; var r net.Resolver; var _ = r`,
		"net.Dialer":            `import "net"; var d = &net.Dialer{}; var _ = d`,
		"net.FileConn":          `import "net"; var _ = net.FileConn`,
		"net.Interfaces":        `import "net"; var _ = net.Interfaces`,
		"http.Get":              `import "net/http"; var _ = http.Get`,
		"http.Post":             `import "net/http"; var _ = http.Post`,
		"http.Head":             `import "net/http"; var _ = http.Head`,
		"http.DefaultClient":    `import "net/http"; var _ = http.DefaultClient`,
		"http.DefaultTransport": `import "net/http"; var _ = http.DefaultTransport`,
		"http.Client":           `import "net/http"; var c = &http.Client{}; var _ = c`,
		"bare transport":        `import "net/http"; var tr = &http.Transport{}; var _ = tr`,
		"transport var":         `import "net/http"; var tr http.Transport; var _ = &tr`,
		"new transport":         `import "net/http"; var tr = new(http.Transport); var _ = tr`,
		"nil DialContext":       `import "net/http"; var tr = &http.Transport{DialContext: nil}; var _ = tr`,
		"transport proxy":       `import ("context"; "net"; "net/http"); var tr = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }, Proxy: nil}; var _ = tr`,
		"transport DialTLS":     `import ("context"; "net"; "net/http"); var tr = &http.Transport{DialContext: nil, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}; var _ = tr`,
		"tls.Dial":              `import "crypto/tls"; var _ = tls.Dial`,
		"tls.Dialer":            `import "crypto/tls"; var _ = tls.Dialer{}`,
		"dot import":            `import . "net"; var _ = Dial`,
		"httptest":              `import "net/http/httptest"; var _ = httptest.NewServer`,
		"linkname":              "import _ \"unsafe\"\n//go:linkname x runtime.x\nvar x int",
		"os.StartProcess":       `import "os"; var _ = os.StartProcess`,
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			if got := check(t, src); len(got) == 0 {
				t.Fatalf("guard missed:\n%s", src)
			}
		})
	}

	good := map[string]string{
		"transport with DialContext": `import ("context"; "crypto/tls"; "net"; "net/http")
var tr = &http.Transport{
	DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
	TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	DisableKeepAlives: true,
}
var _ = tr`,
		"net types":      `import "net"; var _ net.Conn; var _ = net.JoinHostPort("a", "1"); var _ *net.OpError`,
		"http requests":  `import "net/http"; var _ = http.NewRequest; var _ http.Header; var _ = http.MethodHead`,
		"module imports": `import ("github.com/hopbits/client/module"; "google.golang.org/protobuf/proto"); var _ module.Module; var _ = proto.Marshal`,
	}
	for name, src := range good {
		t.Run(name, func(t *testing.T) {
			if got := check(t, src); len(got) != 0 {
				t.Fatalf("guard flagged allowed code: %q", got)
			}
		})
	}
}

func check(t *testing.T, body string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mod.go", "package mod\n"+body+"\n", parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, body)
	}
	return checkFile(fset, f)
}

func TestGuardRefusesForeignSources(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evil")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.go"), []byte("package evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "raw_amd64.s"), []byte("// raw syscalls\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, files, err := checkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "raw_amd64.s") || files["evil"] != 1 {
		t.Fatalf("problems %q, files %v", problems, files)
	}
}
