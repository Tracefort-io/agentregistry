package registry

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// writeCA writes the test server's certificate as a PEM CA file.
func writeCA(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	require.NoError(t, os.WriteFile(path, block, 0o600))
	return path
}

func TestHTTPClientWithCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not-pem.crt")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	tests := []struct {
		name      string
		caFile    string
		wantErr   string
		reachable bool
	}{
		{name: "trusts the CA file", caFile: writeCA(t, ts), reachable: true},
		{name: "system roots without a CA file", caFile: ""},
		{name: "missing file", caFile: filepath.Join(dir, "none.crt"), wantErr: "read TEST_CA_FILE"},
		{name: "file without certificates", caFile: notPEM, wantErr: "TEST_CA_FILE " + notPEM + " holds no PEM certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := httpClientWithCA(2*time.Second, tt.caFile, "TEST_CA_FILE")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 2*time.Second, client.Timeout)
			resp, err := client.Get(ts.URL)
			if !tt.reachable {
				require.Error(t, err, "a private CA must not be trusted without the CA file")
				return
			}
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	}
}

func TestBuildAuthTrustsAuthzenCA(t *testing.T) {
	var pdpURL string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"policy_decision_point":      pdpURL,
			"access_evaluation_endpoint": pdpURL + "/access/v1/evaluation",
		})
	}))
	defer ts.Close()
	pdpURL = ts.URL

	tests := []struct {
		name    string
		caFile  string
		wantErr bool
	}{
		{name: "with AUTHZEN_CA_CERT_FILE", caFile: writeCA(t, ts)},
		{name: "without it", caFile: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := requiredAuthConfig()
			cfg.AuthzenURL = ts.URL
			cfg.AuthzenCACertFile = tt.caFile
			w, err := buildAuth(context.Background(), cfg, types.AppOptions{})
			require.NoError(t, err)
			_, err = w.pdp.Metadata(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestBuildAuthRejectsUnreadableAuthzenCA(t *testing.T) {
	cfg := requiredAuthConfig()
	cfg.AuthzenCACertFile = filepath.Join(t.TempDir(), "none.crt")
	_, err := buildAuth(context.Background(), cfg, types.AppOptions{})
	require.ErrorContains(t, err, "AUTHZEN_CA_CERT_FILE")
}
