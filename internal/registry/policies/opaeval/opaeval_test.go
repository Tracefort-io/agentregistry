package opaeval

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func files(kv ...string) map[string][]byte {
	out := map[string][]byte{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = []byte(kv[i+1])
	}
	return out
}

func TestFormat(t *testing.T) {
	e := New(time.Second)
	out, probs := e.Format("authzen/a.rego", []byte("package authzen\nallow if {input.x==1}\n"))
	if len(probs) != 0 || string(out) != "package authzen\n\nallow if input.x == 1\n" {
		t.Fatalf("Format = %q, %v", out, probs)
	}
	_, probs = e.Format("authzen/a.rego", []byte("package authzen\n\nallow if {\n"))
	if len(probs) == 0 || probs[0].File != "authzen/a.rego" || probs[0].Row == 0 {
		t.Fatalf("Format(broken) problems = %+v", probs)
	}
}

func TestCheck(t *testing.T) {
	e := New(time.Second)
	for _, tt := range []struct {
		name  string
		files map[string][]byte
		want  string // substring of the first problem; empty for none
	}{
		{name: "valid", files: files("a.rego", "package authzen\n\nallow if input.x == data.authzen.limit\n", "data.json", `{"limit": 1}`)},
		{name: "parse error", files: files("a.rego", "package authzen\n\nallow if {\n"), want: "authzen/a.rego:"},
		{name: "unsafe var", files: files("a.rego", "package authzen\n\nallow if x == 1\n"), want: "var x is unsafe"},
		{name: "http.send blocked", files: files("a.rego", "package authzen\n\nr := http.send({\"method\": \"get\", \"url\": \"http://x\"})\n"), want: "http.send"},
		{name: "opa.runtime blocked", files: files("a.rego", "package authzen\n\nr := opa.runtime()\n"), want: "opa.runtime"},
		{name: "broken test is reported", files: files("a.rego", "package authzen\n", "a_test.rego", "package authzen_test\n\ntest_x if y\n"), want: "unsafe"},
		{name: "bad json data", files: files("a.rego", "package authzen\n", "data.json", "{nope"), want: "invalid data"},
		{name: "non-object data", files: files("a.rego", "package authzen\n", "roles/data.json", "[1]"), want: "must hold an object"},
		{name: "rego v0 syntax refused", files: files("a.rego", "package authzen\n\nallow { true }\n"), want: "authzen/a.rego:"},
	} {
		probs := e.Check("authzen", tt.files)
		switch {
		case tt.want == "" && len(probs) != 0:
			t.Errorf("%s: unexpected problems %+v", tt.name, probs)
		case tt.want != "" && (len(probs) == 0 || !strings.Contains(probs[0].String(), tt.want)):
			t.Errorf("%s: problems = %+v, want %q", tt.name, probs, tt.want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	e := New(time.Second)
	policy := files(
		"registry.rego", "package authzen\n\ndefault allow := false\n\nallow if {\n\tprint(\"checking\", input.user)\n\tinput.user in data.authzen.admins\n}\n",
		"data.json", `{"admins": ["ada"]}`,
		"roles/data.json", `{"readers": ["bob"]}`,
	)
	for _, tt := range []struct {
		name  string
		req   EvalRequest
		want  string
		probs string
	}{
		{name: "default query, admin", req: EvalRequest{Input: map[string]any{"user": "ada"}},
			want: `{"allow":true}`},
		{name: "explicit query", req: EvalRequest{Query: "data.authzen.allow", Input: map[string]any{"user": "eve"}},
			want: `false`},
		{name: "editor data overrides", req: EvalRequest{Query: "data.authzen.allow", Input: map[string]any{"user": "eve"},
			Data: map[string]any{"authzen": map[string]any{"admins": []any{"eve"}}}}, want: `true`},
		{name: "data under its directory", req: EvalRequest{Query: "data.authzen.roles.readers"}, want: `["bob"]`},
		{name: "bad query", req: EvalRequest{Query: "data.authzen.allow =="}, probs: "unexpected eof"},
		{name: "runtime error", req: EvalRequest{Query: `x := to_number("nope")`}, probs: "to_number"},
	} {
		tt.req.Policy, tt.req.Files = "authzen", policy
		res, err := e.Evaluate(context.Background(), tt.req)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if tt.probs != "" {
			if len(res.Problems) == 0 || !strings.Contains(res.Problems[0].Message+res.Problems[0].String(), tt.probs) {
				t.Errorf("%s: problems = %+v, want %q", tt.name, res.Problems, tt.probs)
			}
			continue
		}
		if len(res.Problems) != 0 || len(res.Result) != 1 {
			t.Fatalf("%s: result = %+v", tt.name, res)
		}
		got, _ := json.Marshal(res.Result[0].Expressions[0].Value)
		if tt.name == "default query, admin" {
			var obj map[string]any
			_ = json.Unmarshal(got, &obj)
			got, _ = json.Marshal(map[string]any{"allow": obj["allow"]})
			if res.Query != "data.authzen" || !strings.Contains(res.Output, "checking ada") {
				t.Errorf("%s: query %q, output %q", tt.name, res.Query, res.Output)
			}
		}
		if string(got) != tt.want {
			t.Errorf("%s: value = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestEvaluateTimeout(t *testing.T) {
	e := New(50 * time.Millisecond)
	start := time.Now()
	_, err := e.Evaluate(context.Background(), EvalRequest{
		Policy: "slow", Files: files("a.rego", "package slow\n\nn := count([x | some x in numbers.range(1, 100000000)])\n"),
		Query: "data.slow.n",
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func TestTest(t *testing.T) {
	e := New(time.Second)
	report, err := e.Test(context.Background(), "authzen", files(
		"registry.rego", "package authzen\n\nallow if input.user == \"ada\"\n",
		"registry_test.rego", "package authzen_test\n\nimport data.authzen\n\n"+
			"test_ada if authzen.allow with input as {\"user\": \"ada\"}\n\n"+
			"test_bob if {\n\tprint(\"bob is next\")\n\tauthzen.allow with input as {\"user\": \"bob\"}\n}\n",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed != 1 || report.Failed != 1 || len(report.Results) != 2 {
		t.Fatalf("report = %+v", report)
	}
	bob := report.Results[1]
	if bob.Name != "test_bob" || bob.Pass || bob.File != "authzen/registry_test.rego" || bob.Row == 0 ||
		!strings.Contains(bob.Output, "bob is next") {
		t.Fatalf("test_bob = %+v", bob)
	}
}

// The reference policy in docs/auth/authzen, with its tests, runs as is.
func TestReferencePolicy(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "docs", "auth", "authzen")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string][]byte{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".rego") {
			b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			policy[entry.Name()] = b
		}
	}
	e := New(5 * time.Second)
	if probs := e.Check("authzen", policy); len(probs) != 0 {
		t.Fatalf("Check = %+v", probs)
	}
	report, err := e.Test(context.Background(), "authzen", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 0 || report.Passed < 20 || len(report.Problems) != 0 {
		t.Fatalf("report: passed %d, failed %d, problems %+v", report.Passed, report.Failed, report.Problems)
	}
	res, err := e.Evaluate(context.Background(), EvalRequest{
		Policy: "authzen", Files: policy, Query: "data.authzen.allow",
		Input: map[string]any{
			"subject":  map[string]any{"type": "user", "id": "alice", "properties": map[string]any{"roles": []any{"registry-reader"}}},
			"action":   map[string]any{"name": "read"},
			"resource": map[string]any{"type": "agent", "id": "team/x"},
		},
	})
	if err != nil || len(res.Problems) != 0 || len(res.Result) != 1 || res.Result[0].Expressions[0].Value != true {
		t.Fatalf("Evaluate = %+v, %v", res, err)
	}
}

// OPA loads data.json as JSON, so YAML in it is a problem, even though YAML is a superset.
func TestCheckDataIsJSON(t *testing.T) {
	probs := New(time.Second).Check("authzen", files("a.rego", "package authzen\n", "data.json", "admins:\n  - ada\n"))
	if len(probs) == 0 || !strings.Contains(probs[0].Message, "invalid data") {
		t.Fatalf("problems = %+v, want invalid data", probs)
	}
}
