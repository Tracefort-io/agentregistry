package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// DefaultKubernetesTokenFile is the pod's service account token.
const DefaultKubernetesTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// KubernetesAuth logs in with the pod's service account token, which
// OpenBao checks with the Kubernetes API (the kubernetes auth method).
type KubernetesAuth struct {
	// Mount is the auth method's path (default "kubernetes").
	Mount string
	// Role is the OpenBao role bound to the service account.
	Role string
	// TokenFile holds the service account token (default
	// DefaultKubernetesTokenFile). It is read at every login, so a
	// rotated token is picked up.
	TokenFile string
}

// Login implements Auth.
func (a KubernetesAuth) Login(ctx context.Context, c *Client) (Login, error) {
	if a.Role == "" {
		return Login{}, errors.New("kubernetes auth needs a role")
	}
	jwt, err := readCredential(orDefault(a.TokenFile, DefaultKubernetesTokenFile), "service account token")
	if err != nil {
		return Login{}, err
	}
	return login(ctx, c, orDefault(a.Mount, "kubernetes"), map[string]any{"role": a.Role, "jwt": jwt})
}

// AppRoleAuth logs in with a role ID and secret ID (the approle auth
// method), for registries outside Kubernetes.
type AppRoleAuth struct {
	// Mount is the auth method's path (default "approle").
	Mount        string
	RoleIDFile   string
	SecretIDFile string
}

// Login implements Auth.
func (a AppRoleAuth) Login(ctx context.Context, c *Client) (Login, error) {
	roleID, err := readCredential(a.RoleIDFile, "AppRole role ID")
	if err != nil {
		return Login{}, err
	}
	secretID, err := readCredential(a.SecretIDFile, "AppRole secret ID")
	if err != nil {
		return Login{}, err
	}
	return login(ctx, c, orDefault(a.Mount, "approle"), map[string]any{"role_id": roleID, "secret_id": secretID})
}

// TokenAuth uses a token from a file as is, for development or a token
// managed by an agent. The file is read again whenever OpenBao refuses the
// current token.
type TokenAuth struct {
	TokenFile string
}

// Login implements Auth.
func (a TokenAuth) Login(context.Context, *Client) (Login, error) {
	token, err := readCredential(a.TokenFile, "token")
	if err != nil {
		return Login{}, err
	}
	return Login{Token: token}, nil
}

func login(ctx context.Context, c *Client, mount string, body map[string]any) (Login, error) {
	var resp authResponse
	if err := c.Unauthenticated(ctx, http.MethodPost, "auth/"+strings.Trim(mount, "/")+"/login", body, &resp); err != nil {
		return Login{}, err
	}
	l := resp.login()
	if l.Token == "" {
		return Login{}, errors.New("login response has no client token")
	}
	return l, nil
}

func readCredential(path, what string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no file configured for the %s", what)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path comes from operator configuration
	if err != nil {
		return "", fmt.Errorf("read %s: %w", what, err)
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("%s file %s is empty", what, path)
	}
	return v, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
