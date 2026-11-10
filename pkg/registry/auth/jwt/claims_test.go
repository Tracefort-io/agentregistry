package jwt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

func TestStringsAt(t *testing.T) {
	claims := map[string]any{
		"roles":        []any{"a", 7, "", "b"},
		"single":       "only",
		"realm_access": map[string]any{"roles": []any{"realm-role"}},
		"resource_access": map[string]any{
			"registry":        map[string]any{"roles": []any{"client-role"}},
			"my.dotted.app":   map[string]any{"roles": []any{"dotted-role"}},
			"my":              map[string]any{"other": "x"},
			"flat.key.at.top": "nope",
		},
		"a.b": []any{"literal-dotted-key"},
	}
	tests := []struct {
		path string
		want []string
	}{
		{"roles", []string{"a", "b"}},
		{"single", []string{"only"}},
		{"realm_access.roles", []string{"realm-role"}},
		{"resource_access.registry.roles", []string{"client-role"}},
		{"resource_access.my.dotted.app.roles", []string{"dotted-role"}},
		{"a.b", []string{"literal-dotted-key"}},
		{"resource_access.missing.roles", nil},
		{"realm_access", nil},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, nilIfEmpty(stringsAt(claims, tt.path)))
		})
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func TestParseActors(t *testing.T) {
	deep := map[string]any{"sub": "leaf"}
	for i := 0; i < maxActorDepth; i++ {
		deep = map[string]any{"sub": "a", "act": deep}
	}
	tests := []struct {
		name    string
		act     any
		want    []auth.Actor
		wantErr string
	}{
		{name: "absent", act: nil, want: nil},
		{name: "single", act: map[string]any{"sub": "svc", "iss": "https://i"}, want: []auth.Actor{{Subject: "svc", Issuer: "https://i"}}},
		{
			name: "chain outermost first",
			act:  map[string]any{"sub": "current", "act": map[string]any{"sub": "prior", "act": map[string]any{"sub": "first"}}},
			want: []auth.Actor{{Subject: "current"}, {Subject: "prior"}, {Subject: "first"}},
		},
		{name: "not an object", act: "svc", wantErr: "not an object"},
		{name: "no subject", act: map[string]any{"iss": "https://i"}, wantErr: "no subject"},
		{name: "too deep", act: deep, wantErr: "too deeply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseActors(tt.act)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestTruthy(t *testing.T) {
	tests := []struct {
		v    any
		want bool
	}{
		{nil, false}, {false, false}, {true, true},
		{"", false}, {"false", false}, {"0", false}, {"app", true}, {"True", true},
		{float64(0), false}, {float64(1), true},
		{[]any{}, false}, {[]any{"x"}, true},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, truthy(tt.v), "truthy(%#v)", tt.v)
	}
}

func TestIsClientToken(t *testing.T) {
	require.True(t, IsClientToken(auth.Principal{Subject: "c", ClientID: "c"}))
	require.False(t, IsClientToken(auth.Principal{Subject: "u", ClientID: "c"}))
	require.False(t, IsClientToken(auth.Principal{Subject: "u"}))
	require.False(t, IsClientSession(&auth.PublicSession{}))
}

func TestBearerTokenNeverEchoed(t *testing.T) {
	secret := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	for _, header := range []string{"Basic " + secret, "Bearer " + secret + " extra"} {
		_, err := bearerToken(header)
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), secret))
	}
}
