package jwt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIssuers(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
		check   func(t *testing.T, got []IssuerConfig)
	}{
		{
			name:  "defaults applied",
			input: `[{"issuer":"https://kc.example/realms/r","audiences":["agentregistry"]}]`,
			check: func(t *testing.T, got []IssuerConfig) {
				require.Len(t, got, 1)
				c := got[0]
				require.Equal(t, []string{"RS256", "ES256"}, c.Algorithms)
				require.Equal(t, "sub", c.SubjectClaim)
				require.Equal(t, "realm_access.roles", c.RolesClaim)
				require.Equal(t, "groups", c.GroupsClaim)
				require.Empty(t, c.JWKSURI)
				require.Equal(t, []string{"preferred_username", "upn", "email"}, c.usernameClaims())
				require.Equal(t, []string{"azp", "client_id"}, c.clientIDClaims())
			},
		},
		{
			name: "all fields",
			input: `[{"issuer":"https://login.microsoftonline.com/t/v2.0","audiences":["api://registry"],
				"jwksUri":"https://login.microsoftonline.com/t/discovery/v2.0/keys","algorithms":["RS256"],
				"subjectClaim":"oid","usernameClaim":"upn","clientIdClaim":"appid","rolesClaim":"roles",
				"groupsClaim":"groups","clientSubjectClaim":"idtyp"}]`,
			check: func(t *testing.T, got []IssuerConfig) {
				c := got[0]
				require.Equal(t, "oid", c.SubjectClaim)
				require.Equal(t, []string{"upn"}, c.usernameClaims())
				require.Equal(t, []string{"appid"}, c.clientIDClaims())
				require.Equal(t, "roles", c.RolesClaim)
				require.Equal(t, "idtyp", c.ClientSubjectClaim)
			},
		},
		{name: "bad JSON", input: `[{"issuer":`, wantErr: "decoding issuers"},
		{name: "not an array", input: `{"issuer":"https://a.example"}`, wantErr: "decoding issuers"},
		{name: "unknown field", input: `[{"issuer":"https://a.example","audiences":["a"],"audience":"a"}]`, wantErr: "unknown field"},
		{name: "trailing data", input: `[] []`, wantErr: "unexpected data"},
		{name: "empty array", input: `[]`, wantErr: "at least one issuer"},
		{name: "missing issuer", input: `[{"audiences":["a"]}]`, wantErr: "issuer is required"},
		{name: "relative issuer", input: `[{"issuer":"kc/realms/r","audiences":["a"]}]`, wantErr: "absolute http(s) URL"},
		{name: "no audience", input: `[{"issuer":"https://a.example"}]`, wantErr: "at least one audience"},
		{name: "blank audience", input: `[{"issuer":"https://a.example","audiences":[" "]}]`, wantErr: "at least one audience"},
		{name: "HS256", input: `[{"issuer":"https://a.example","audiences":["a"],"algorithms":["RS256","HS256"]}]`, wantErr: `"HS256" is not allowed`},
		{name: "none", input: `[{"issuer":"https://a.example","audiences":["a"],"algorithms":["none"]}]`, wantErr: `"none" is not allowed`},
		{name: "bad jwks uri", input: `[{"issuer":"https://a.example","audiences":["a"],"jwksUri":"file:///keys"}]`, wantErr: "jwksUri"},
		{
			name:    "duplicate issuer",
			input:   `[{"issuer":"https://a.example","audiences":["a"]},{"issuer":"https://a.example","audiences":["b"]}]`,
			wantErr: "duplicate issuer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIssuers(tt.input)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			tt.check(t, got)
		})
	}
}

func TestLoadIssuers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "issuers.json")
	require.NoError(t, os.WriteFile(file, []byte(`[{"issuer":"https://file.example","audiences":["a"]}]`), 0o600))
	inline := `[{"issuer":"https://inline.example","audiences":["a"]}]`

	tests := []struct {
		name       string
		inline     string
		file       string
		wantIssuer string
		wantErr    bool
	}{
		{name: "inline only", inline: inline, wantIssuer: "https://inline.example"},
		{name: "file only", file: file, wantIssuer: "https://file.example"},
		{name: "file wins", inline: inline, file: file, wantIssuer: "https://file.example"},
		{name: "missing file", inline: inline, file: filepath.Join(dir, "missing.json"), wantErr: true},
		{name: "nothing configured", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadIssuers(tt.inline, tt.file)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantIssuer, got[0].Issuer)
		})
	}
}
