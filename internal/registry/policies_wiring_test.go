package registry

import (
	"net/url"
	"testing"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
)

func TestGitUserinfo(t *testing.T) {
	for _, tt := range []struct {
		provider string
		in       *url.Userinfo
		want     string
	}{
		{provider: "github", in: url.User("ghp_token"), want: "x-access-token:ghp_token"},
		{provider: "gitlab", in: url.User("glpat-token"), want: "oauth2:glpat-token"},
		{provider: "gitlab", in: url.UserPassword("bot", "glpat-token"), want: "bot:glpat-token"},
		{provider: "github", in: nil, want: ""},
	} {
		got := gitUserinfo(tt.provider, tt.in)
		if (got == nil && tt.want != "") || (got != nil && got.String() != tt.want) {
			t.Errorf("gitUserinfo(%s, %v) = %v, want %q", tt.provider, tt.in, got, tt.want)
		}
	}
}

func TestBuildPoliciesOff(t *testing.T) {
	svc, webhook, err := buildPolicies(&config.Config{}, nil, nil, nil)
	if svc != nil || webhook != nil || err != nil {
		t.Fatalf("buildPolicies(off) = %v, %v, %v; want nothing", svc, webhook, err)
	}
}
