// Package opaeval formats, checks, evaluates and tests Rego for the policy
// editor, in process with the OPA library. Rego here is written by users,
// so evaluation is restricted: built-ins that reach the network or the
// host (http.send, net.lookup_ip_addr, opa.runtime) are removed from the
// capabilities, so a policy using them doesn't compile, and every run is
// bounded by a timeout.
package opaeval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/format"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/util"
)

// blockedBuiltins reach outside the process.
var blockedBuiltins = []string{"http.send", "net.lookup_ip_addr", "opa.runtime"}

const maxOutputBytes = 64 << 10

// ErrTimeout is a run stopped by the timeout.
var ErrTimeout = errors.New("evaluation timed out")

// RegoProblem is one error in a file, with a 1-based position when known.
type RegoProblem struct {
	File    string `json:"file,omitempty"`
	Row     int    `json:"row,omitempty"`
	Col     int    `json:"col,omitempty"`
	Message string `json:"message"`
}

// Engine runs the editor's tools.
type Engine struct {
	timeout      time.Duration
	capabilities *ast.Capabilities
}

// New returns an Engine whose evaluations and test runs stop after timeout.
func New(timeout time.Duration) *Engine {
	caps := ast.CapabilitiesForThisVersion()
	caps.Builtins = slices.DeleteFunc(slices.Clone(caps.Builtins), func(b *ast.Builtin) bool {
		return slices.Contains(blockedBuiltins, b.Name)
	})
	caps.AllowNet = []string{}
	return &Engine{timeout: timeout, capabilities: caps}
}

// Format returns src formatted as `opa fmt` would, or the parse problems.
func (e *Engine) Format(file string, src []byte) ([]byte, []RegoProblem) {
	out, err := format.SourceWithOpts(file, src, format.Opts{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, problems(err, file)
	}
	return out, nil
}

// Check parses and compiles a policy's files (paths relative to the
// policy) and parses its data files. It returns every problem found.
func (e *Engine) Check(policy string, files map[string][]byte) []RegoProblem {
	_, _, probs := e.compile(policy, files)
	return probs
}

// EvalRequest is one evaluation of a policy.
type EvalRequest struct {
	Policy string
	// Files are the policy's files, paths relative to the policy.
	Files map[string][]byte
	// Query is a Rego query; empty evaluates the first non-test package.
	Query string
	// Input is the value of input; nil leaves input undefined.
	Input any
	// Data is merged over the data the policy's data files provide.
	Data map[string]any
}

// RegoEvalResult is what an evaluation produced.
type RegoEvalResult struct {
	Query    string         `json:"query"`
	Result   rego.ResultSet `json:"result"`
	Output   string         `json:"output,omitempty"`
	Problems []RegoProblem  `json:"problems,omitempty"`
	Duration time.Duration  `json:"durationNs"`
}

// Evaluate runs a query against the policy with the given input and data.
// Problems in the policy or query are reported in the result, not as an
// error; the error is for a timeout or a failure of the engine.
func (e *Engine) Evaluate(ctx context.Context, req EvalRequest) (RegoEvalResult, error) {
	modules, data, probs := e.compile(req.Policy, req.Files)
	query := strings.TrimSpace(req.Query)
	if query == "" {
		query = defaultQuery(modules)
	}
	res := RegoEvalResult{Query: query, Problems: probs}
	if len(probs) > 0 {
		return res, nil
	}
	merged := deepMerge(data, req.Data)
	var out bytes.Buffer
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Store(inmem.NewFromObject(merged)),
		rego.Capabilities(e.capabilities),
		rego.EnablePrintStatements(true),
		rego.PrintHook(topdown.NewPrintHook(&limitedWriter{w: &out, n: maxOutputBytes})),
		rego.StrictBuiltinErrors(true),
		rego.SetRegoVersion(ast.RegoV1),
	}
	for _, m := range modules {
		opts = append(opts, rego.ParsedModule(m))
	}
	if req.Input != nil {
		opts = append(opts, rego.Input(req.Input))
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	start := time.Now()
	rs, err := rego.New(opts...).Eval(ctx)
	res.Duration = time.Since(start)
	res.Output = out.String()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return res, fmt.Errorf("%w after %s", ErrTimeout, e.timeout)
	case err != nil:
		res.Problems = problems(err, "")
		return res, nil
	}
	if rs == nil {
		rs = rego.ResultSet{}
	}
	res.Result = rs
	return res, nil
}

// RegoTestResult is one test rule's outcome.
type RegoTestResult struct {
	File     string        `json:"file"`
	Row      int           `json:"row"`
	Package  string        `json:"package"`
	Name     string        `json:"name"`
	Pass     bool          `json:"pass"`
	Skip     bool          `json:"skip,omitempty"`
	Error    string        `json:"error,omitempty"`
	Output   string        `json:"output,omitempty"`
	Duration time.Duration `json:"durationNs"`
}

// RegoTestReport is the outcome of running a policy's tests.
type RegoTestReport struct {
	Results  []RegoTestResult `json:"results"`
	Problems []RegoProblem    `json:"problems,omitempty"`
	Passed   int              `json:"passed"`
	Failed   int              `json:"failed"`
}

// Test runs the test_ rules in the policy's files with its data loaded.
func (e *Engine) Test(ctx context.Context, policy string, files map[string][]byte, extra map[string]any) (RegoTestReport, error) {
	modules, data, probs := e.compile(policy, files)
	report := RegoTestReport{Results: []RegoTestResult{}, Problems: probs}
	if len(probs) > 0 {
		return report, nil
	}
	compiler := ast.NewCompiler().WithCapabilities(e.capabilities).WithEnablePrintStatements(true).
		WithDefaultRegoVersion(ast.RegoV1)
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	ch, err := tester.NewRunner().
		SetCompiler(compiler).
		SetStore(inmem.NewFromObject(deepMerge(data, extra))).
		CapturePrintOutput(true).
		SetTimeout(e.timeout).
		SetModules(modules).
		RunTests(ctx, nil)
	if err != nil {
		report.Problems = problems(err, "")
		return report, nil
	}
	for r := range ch {
		tr := RegoTestResult{Package: strings.TrimPrefix(r.Package, "data."), Name: r.Name, Skip: r.Skip,
			Duration: r.Duration, Output: truncate(string(r.Output))}
		if r.Location != nil {
			tr.File, tr.Row = r.Location.File, r.Location.Row
		}
		switch {
		case r.Error != nil:
			tr.Error = r.Error.Error()
		case r.Fail:
			tr.Error = "fail"
		case !r.Skip:
			tr.Pass = true
		}
		if tr.Pass {
			report.Passed++
		} else if !tr.Skip {
			report.Failed++
		}
		report.Results = append(report.Results, tr)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return report, fmt.Errorf("%w after %s", ErrTimeout, e.timeout)
	}
	slices.SortFunc(report.Results, func(a, b RegoTestResult) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		return a.Row - b.Row
	})
	return report, nil
}

// compile parses and compiles the policy's Rego (tests included, so a
// broken test is reported) and loads its data files. Module keys and problem
// files are "<policy>/<path>".
func (e *Engine) compile(policy string, files map[string][]byte) (map[string]*ast.Module, map[string]any, []RegoProblem) {
	modules := map[string]*ast.Module{}
	data := map[string]any{}
	var probs []RegoProblem
	opts := ast.ParserOptions{RegoVersion: ast.RegoV1, ProcessAnnotation: true, Capabilities: e.capabilities}
	for _, rel := range sortedKeys(files) {
		name := path.Join(policy, rel)
		switch {
		case strings.HasSuffix(rel, ".rego"):
			m, err := ast.ParseModuleWithOpts(name, string(files[rel]), opts)
			if err != nil {
				probs = append(probs, problems(err, name)...)
				continue
			}
			modules[name] = m
		case path.Base(rel) == "data.json":
			var v any
			if err := util.UnmarshalJSON(files[rel], &v); err != nil {
				probs = append(probs, RegoProblem{File: name, Message: "invalid data: " + err.Error()})
				continue
			}
			if err := insertData(data, dataKeys(name), v); err != nil {
				probs = append(probs, RegoProblem{File: name, Message: err.Error()})
			}
		}
	}
	if len(probs) > 0 {
		return modules, data, probs
	}
	compiler := ast.NewCompiler().WithCapabilities(e.capabilities).WithEnablePrintStatements(true).
		WithDefaultRegoVersion(ast.RegoV1)
	if compiler.Compile(modules); compiler.Failed() {
		probs = append(probs, problems(compiler.Errors, "")...)
	}
	return modules, data, probs
}

// dataKeys is where an OPA bundle loads a data file: under its directory.
func dataKeys(file string) []string {
	dir := path.Dir(file)
	if dir == "." {
		return nil
	}
	return strings.Split(dir, "/")
}

func insertData(root map[string]any, keys []string, v any) error {
	node := root
	for _, k := range keys {
		next, ok := node[k]
		if !ok {
			child := map[string]any{}
			node[k] = child
			node = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("data at %s is not an object", strings.Join(keys, "."))
		}
		node = child
	}
	obj, ok := v.(map[string]any)
	if !ok {
		if len(keys) == 0 {
			return errors.New("top-level data must be an object")
		}
		return fmt.Errorf("data file under %s must hold an object", strings.Join(keys, "."))
	}
	maps.Copy(node, obj)
	return nil
}

// deepMerge returns base with over merged in; values in over win.
func deepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	maps.Copy(out, base)
	for k, v := range over {
		if bm, ok := out[k].(map[string]any); ok {
			if om, ok := v.(map[string]any); ok {
				out[k] = deepMerge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// defaultQuery evaluates the first non-test package.
func defaultQuery(modules map[string]*ast.Module) string {
	for _, name := range sortedModuleKeys(modules) {
		if strings.HasSuffix(name, "_test.rego") {
			continue
		}
		return modules[name].Package.Path.String()
	}
	return "data"
}

func problems(err error, file string) []RegoProblem {
	var errs ast.Errors
	if errors.As(err, &errs) {
		out := make([]RegoProblem, 0, len(errs))
		for _, e := range errs {
			p := RegoProblem{File: file, Message: e.Message}
			if e.Location != nil {
				p.File, p.Row, p.Col = e.Location.File, e.Location.Row, e.Location.Col
			}
			out = append(out, p)
		}
		return out
	}
	var one *ast.Error
	if errors.As(err, &one) {
		return problems(ast.Errors{one}, file)
	}
	var topdownErr *topdown.Error
	if errors.As(err, &topdownErr) {
		p := RegoProblem{Message: topdownErr.Message}
		if topdownErr.Location != nil {
			p.File, p.Row, p.Col = topdownErr.Location.File, topdownErr.Location.Row, topdownErr.Location.Col
		}
		return []RegoProblem{p}
	}
	return []RegoProblem{{File: file, Message: err.Error()}}
}

// String is "file:row:col: message".
func (p RegoProblem) String() string {
	switch {
	case p.File != "" && p.Row > 0:
		return fmt.Sprintf("%s:%d:%d: %s", p.File, p.Row, p.Col, p.Message)
	case p.File != "":
		return p.File + ": " + p.Message
	default:
		return p.Message
	}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func sortedModuleKeys(m map[string]*ast.Module) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func truncate(s string) string {
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "\n... output truncated"
	}
	return s
}

// limitedWriter keeps the first n bytes written and drops the rest.
type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		l.w.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
