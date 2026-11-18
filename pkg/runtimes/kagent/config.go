// Package kagent provides AgentRegistry deployment and discovery support for
// Kagent 1.x. Kagent 1.x keeps agents and MCP servers as Kubernetes resources
// in the api.kagent.dev group, so the adapter reads and writes them through
// the Kubernetes API, using the registry's in-cluster ServiceAccount.
package kagent

import (
	"encoding/json"
	"fmt"
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

const (
	RuntimeType             = "Kagent"
	defaultRuntimeNamespace = "kagent"
)

// Registers Kagent with the admission validator so Runtime{spec.type: Kagent} passes Validate.
func init() {
	v1alpha1.KnownRuntimeTypes[RuntimeType] = struct{}{}
	if err := v1alpha1.RegisterRuntimeConfigValidator(RuntimeType, validateRuntimeConfigForAdmission); err != nil {
		panic(err)
	}
}

func validateRuntimeConfigForAdmission(config map[string]any) error {
	_, err := decodeRuntimeConfig(config)
	return err
}

// runtimeConfig is a Kagent Runtime's spec.config.
type runtimeConfig struct {
	// Namespace is where Kagent's resources live; defaults to "kagent".
	Namespace string `json:"namespace,omitempty"`
	// URL is Kagent 0.10's REST endpoint. Kagent 1.x is reached through the
	// Kubernetes API instead, so it is accepted for existing Runtimes and ignored.
	URL        string                  `json:"kagentUrl,omitempty"`
	Deployment runtimeDeploymentConfig `json:"deployment,omitempty"`
}

type runtimeDeploymentConfig struct {
	// Labels are added to every resource the adapter creates.
	Labels map[string]string `json:"labels,omitempty"`
}

func decodeJSONMap(m map[string]any, target any) error {
	if len(m) == 0 {
		return nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func decodeRuntimeConfig(m map[string]any) (runtimeConfig, error) {
	for key := range m {
		if strings.EqualFold(key, "auth") {
			return runtimeConfig{}, fmt.Errorf(
				"kagent runtime config: auth is not supported; Kagent 1.x is reached through the Kubernetes API with the registry's ServiceAccount",
			)
		}
	}
	var cfg runtimeConfig
	if err := decodeJSONMap(m, &cfg); err != nil {
		return runtimeConfig{}, fmt.Errorf("decode kagent runtime config: %w", err)
	}
	if cfg.Namespace != "" {
		if problems := k8svalidation.IsDNS1123Label(cfg.Namespace); len(problems) > 0 {
			return runtimeConfig{}, fmt.Errorf(
				"kagent runtime config: namespace %q: %s", cfg.Namespace, strings.Join(problems, "; "),
			)
		}
	}
	for key, value := range cfg.Deployment.Labels {
		if problems := k8svalidation.IsQualifiedName(key); len(problems) > 0 {
			return runtimeConfig{}, fmt.Errorf(
				"kagent runtime config: deployment.labels key %q: %s", key, strings.Join(problems, "; "),
			)
		}
		if problems := k8svalidation.IsValidLabelValue(value); len(problems) > 0 {
			return runtimeConfig{}, fmt.Errorf(
				"kagent runtime config: deployment.labels[%q] value %q: %s", key, value, strings.Join(problems, "; "),
			)
		}
	}
	return cfg, nil
}

// decodeDeployConfig rejects any Deployment runtimeConfig: Kagent 1.x
// deployments (remote MCP servers) take no per-Deployment settings.
func decodeDeployConfig(m map[string]any) error {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return fmt.Errorf("runtimeConfig %v is not supported on Kagent 1.x", keys)
}

func targetNamespace(rcfg runtimeConfig) string {
	if rcfg.Namespace != "" {
		return rcfg.Namespace
	}
	return defaultRuntimeNamespace
}

// RuntimeNamespace returns the namespace Kagent resources for this runtime
// config live in. It reads only the namespace key; Apply validates the rest.
func RuntimeNamespace(config map[string]any) string {
	var rcfg runtimeConfig
	if err := decodeJSONMap(config, &rcfg); err != nil {
		return defaultRuntimeNamespace
	}
	return targetNamespace(rcfg)
}
