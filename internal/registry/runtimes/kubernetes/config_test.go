package kubernetes

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func validRuntimeConfig() map[string]any {
	return map[string]any{
		"trustDomain": "tracefort.localhost",
		"gateway": map[string]any{
			"url":       "https://tracefort-agentgateway.tracefort-control-plane.svc:8443",
			"spiffeID":  "spiffe://tracefort.localhost/gateway/tracefort-control-plane/tracefort-agentgateway",
			"namespace": "tracefort-control-plane",
			"podLabels": map[string]any{"gateway.networking.k8s.io/gateway-name": "tracefort-agentgateway"},
		},
		"temporal": map[string]any{"address": "tracefort-agentgateway.tracefort-control-plane.svc:7234"},
	}
}

func withConfig(change func(m map[string]any)) map[string]any {
	m := validRuntimeConfig()
	gateway := maps.Clone(m["gateway"].(map[string]any))
	m["gateway"] = gateway
	change(m)
	return m
}

func TestDecodeRuntimeConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]any
		wantErr string
	}{
		{"valid", validRuntimeConfig(), ""},
		{"no trust domain", withConfig(func(m map[string]any) { delete(m, "trustDomain") }), "trustDomain"},
		{"trust domain not a DNS name", withConfig(func(m map[string]any) { m["trustDomain"] = "Trace Fort" }), "trustDomain"},
		{"gateway over http", withConfig(func(m map[string]any) { m["gateway"].(map[string]any)["url"] = "http://gw:8081" }), "https"},
		{"gateway ID in another trust domain", withConfig(func(m map[string]any) {
			m["gateway"].(map[string]any)["spiffeID"] = "spiffe://evil.example/gateway"
		}), "trust domain"},
		{"no gateway pod labels", withConfig(func(m map[string]any) { delete(m["gateway"].(map[string]any), "podLabels") }), "podLabels"},
		{"bad gateway namespace", withConfig(func(m map[string]any) { m["gateway"].(map[string]any)["namespace"] = "Not_A_Label" }), "gateway.namespace"},
		{"no temporal address", withConfig(func(m map[string]any) { delete(m, "temporal") }), "temporal.address"},
		{"bad namespace prefix", withConfig(func(m map[string]any) { m["namespacePrefix"] = "Org_" }), "namespacePrefix"},
		{"unknown key", withConfig(func(m map[string]any) { m["auth"] = map[string]any{} }), "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := decodeRuntimeConfig(tt.config)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "org-", cfg.NamespacePrefix)
		})
	}
}

func TestDecodeDeployConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       map[string]any
		wantReplicas int32
		wantErr      string
	}{
		{"empty", nil, 1, ""},
		{"replicas", map[string]any{"replicas": 3}, 3, ""},
		{"zero replicas", map[string]any{"replicas": 0}, 0, "between 1"},
		{"too many replicas", map[string]any{"replicas": maxReplicas + 1}, 0, "between 1"},
		{"unknown key", map[string]any{"image": "x"}, 0, "unknown field"},
		{"command, args and user", map[string]any{"command": []any{"/bin/agent"}, "args": []any{"--port", "8080"}, "runAsUser": 65532}, 1, ""},
		{"root user", map[string]any{"runAsUser": 0}, 0, "non-root"},
		{"negative user", map[string]any{"runAsUser": -1}, 0, "non-root"},
		{"empty argument", map[string]any{"args": []any{"run", ""}}, 0, "args[1]"},
		{"too many arguments", map[string]any{"command": make([]any, maxArgs+1)}, 0, "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := decodeDeployConfig(tt.config)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantReplicas, cfg.replicas())
		})
	}
}
