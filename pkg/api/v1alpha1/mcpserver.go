package v1alpha1

// MCPServer is the typed envelope for kind=MCPServer resources.
type MCPServer struct {
	TypeMeta `json:",inline" yaml:",inline"`
	Metadata ObjectMeta    `json:"metadata" yaml:"metadata"`
	Spec     MCPServerSpec `json:"spec" yaml:"spec"`
	Status   Status        `json:"status,omitzero" yaml:"status,omitempty"`
}

func init() {
	MustRegisterKind[*MCPServer, MCPServerSpec](KindMCPServer)
}

// MCPServerSpec is the MCP server's declarative body.
type MCPServerSpec struct {
	Title       string `json:"title,omitempty" yaml:"title,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// IconURL is the image a catalog UI shows for this MCP server. Either an
	// absolute https:// URL or a root-relative path served by the UI.
	IconURL string `json:"iconUrl,omitempty" yaml:"iconUrl,omitempty"`

	// Source declares where the bundled MCP server comes from — Package (the
	// runnable distribution) and/or Repository (the source code).
	Source *MCPServerSource `json:"source,omitempty" yaml:"source,omitempty"`

	// Remote declares a remote MCP server instead of a bundled one. These are pre-existing
	// MCP servers that the registry does not deploy but can be referenced by Agents.
	Remote *MCPRemote `json:"remote,omitempty" yaml:"remote,omitempty"`

	// Credential is what the gateway presents to this MCP server on calls
	// from agents. Agents never hold it: the gateway fetches it from the
	// secret store after authorizing the call, and the store lets it do so
	// only for agents that list this server.
	Credential *MCPCredential `json:"credential,omitempty" yaml:"credential,omitempty"`
}

// MCPCredentialType says what the gateway presents to an MCP server.
type MCPCredentialType string

const (
	// MCPCredentialTypeStatic sends one value of the Secret as it is stored.
	MCPCredentialTypeStatic MCPCredentialType = "Static"
	// MCPCredentialTypeOAuthClientCredentials sends an access token that the
	// gateway gets with the server's OAuth client credentials (RFC 6749
	// section 4.4), held in the Secret.
	MCPCredentialTypeOAuthClientCredentials MCPCredentialType = "OAuthClientCredentials"
)

// MCPCredential names the credential of an MCP server and how it is sent.
type MCPCredential struct {
	// Type defaults to Static.
	Type MCPCredentialType `json:"type,omitempty" yaml:"type,omitempty"`
	// SecretRef is a registry Secret in the MCP server's own namespace; a
	// credential never crosses namespaces. For Static, Key names the value
	// sent; for OAuthClientCredentials, the keys are named in
	// OAuthClientCredentials and Key is not set.
	SecretRef SecretKeyRef `json:"secretRef" yaml:"secretRef"`
	// Header carries a Static credential; defaults to Authorization.
	Header string `json:"header,omitempty" yaml:"header,omitempty"`
	// Scheme, when set, is sent before a Static credential, e.g. "Bearer".
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	// OAuthClientCredentials is required for, and only allowed with, type
	// OAuthClientCredentials. The access token is always sent as
	// "Authorization: Bearer <token>".
	OAuthClientCredentials *MCPOAuthClientCredentials `json:"oauthClientCredentials,omitempty" yaml:"oauthClientCredentials,omitempty"`
}

// MCPOAuthClientCredentials says how the gateway gets an access token for an
// MCP server with the server's OAuth client: a client credentials grant at
// TokenURL, authenticated with client_secret_basic.
type MCPOAuthClientCredentials struct {
	// TokenURL is the authorization server's token endpoint (https).
	TokenURL string `json:"tokenUrl" yaml:"tokenUrl"`
	// ClientIDKey and ClientSecretKey are the keys of SecretRef's Secret
	// holding the client's identifier and secret.
	ClientIDKey     string `json:"clientIdKey" yaml:"clientIdKey"`
	ClientSecretKey string `json:"clientSecretKey" yaml:"clientSecretKey"`
	// Scopes requested; none sends no scope parameter.
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	// Resource is the RFC 8707 resource indicator sent in the token request;
	// defaults to the canonical URI of spec.remote.url, as the MCP
	// authorization specification requires.
	Resource string `json:"resource,omitempty" yaml:"resource,omitempty"`
}

// DefaultCredentialHeader is the header an MCPCredential uses by default.
const DefaultCredentialHeader = "Authorization"

// CredentialType is the credential's type, Static when not set.
func (c *MCPCredential) CredentialType() MCPCredentialType {
	if c == nil || c.Type == "" {
		return MCPCredentialTypeStatic
	}
	return c.Type
}

// HeaderName is the header that carries the credential.
func (c *MCPCredential) HeaderName() string {
	if c == nil || c.Header == "" || c.CredentialType() == MCPCredentialTypeOAuthClientCredentials {
		return DefaultCredentialHeader
	}
	return c.Header
}

// MCPRemote describes a pre-running remote MCP server that the registry
// does not deploy. Distinct from MCPTransport (used inside MCPPackage to
// describe a deployable package's transport) because remote headers carry
// only static name/value pairs - no templating.
type MCPRemote struct {
	Type    string       `json:"type" yaml:"type"`
	URL     string       `json:"url" yaml:"url"`
	Headers []HTTPHeader `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// HTTPHeader is an HTTP header sent on requests to a remote MCP server.
type HTTPHeader struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// MCPServerSource is the distribution origin of a bundled MCP server.
type MCPServerSource struct {
	// Package is the runnable distribution (stdio binary, container image,
	// npm package, etc.) of this MCP server.
	Package *MCPPackage `json:"package,omitempty" yaml:"package,omitempty"`
}

// MCPTransport describes how a deployable MCPPackage exposes itself. Used
// only inside MCPPackage; remotes use MCPRemote, which carries its own URL.
// For http, the listen Port and endpoint Path are set explicitly because the
// host is constructed at deploy time. Both are ignored for stdio.
type MCPTransport struct {
	Type string `json:"type" yaml:"type"`                     // "http" | "stdio"
	Port uint16 `json:"port,omitempty" yaml:"port,omitempty"` // http listen port 1-65535 (ignored for stdio)
	Path string `json:"path,omitempty" yaml:"path,omitempty"` // http endpoint path, e.g. "/mcp" (ignored for stdio)
}

// MCPPackage is a runnable distribution of an MCP server, grouped by
// concern: Origin (what to fetch), Launch (how to start it), Transport
// (how to talk to it).
type MCPPackage struct {
	Origin    MCPPackageOrigin  `json:"origin" yaml:"origin"`
	Launch    *MCPPackageLaunch `json:"launch,omitempty" yaml:"launch,omitempty"`
	Transport MCPTransport      `json:"transport" yaml:"transport"`
}

// MCPPackageOrigin identifies the package and where to fetch it. The Type
// discriminator selects which per-type sub-struct must be set; exactly one
// of NPM/PyPI/OCI is non-nil, matching Type.
type MCPPackageOrigin struct {
	Type       MCPPackageOriginType `json:"type" yaml:"type"`
	Identifier string               `json:"identifier" yaml:"identifier"`

	NPM  *MCPPackageOriginNPM  `json:"npm,omitempty"  yaml:"npm,omitempty"`
	PyPI *MCPPackageOriginPyPI `json:"pypi,omitempty" yaml:"pypi,omitempty"`
	OCI  *MCPPackageOriginOCI  `json:"oci,omitempty"  yaml:"oci,omitempty"`
}

type MCPPackageOriginType string

const (
	MCPPackageOriginTypeNPM  MCPPackageOriginType = "npm"
	MCPPackageOriginTypePyPI MCPPackageOriginType = "pypi"
	MCPPackageOriginTypeOCI  MCPPackageOriginType = "oci"
)

// MCPPackageOriginNPM holds npm-specific fetch inputs.
type MCPPackageOriginNPM struct {
	Version    string `json:"version" yaml:"version"`
	Mirror     string `json:"mirror,omitempty" yaml:"mirror,omitempty"`
	ServerName string `json:"serverName" yaml:"serverName"`
}

// MCPPackageOriginPyPI holds pypi-specific fetch inputs.
type MCPPackageOriginPyPI struct {
	Version    string `json:"version" yaml:"version"`
	Mirror     string `json:"mirror,omitempty" yaml:"mirror,omitempty"`
	ServerName string `json:"serverName" yaml:"serverName"`
}

// MCPPackageOriginOCI holds oci-specific fetch inputs. Version is encoded
// in Identifier (e.g. "ghcr.io/foo/bar:1.0.0" or "...@sha256:..."); bare
// image refs that would silently resolve `:latest` are rejected by the
// validator.
type MCPPackageOriginOCI struct {
	ServerName string `json:"serverName" yaml:"serverName"`
}

// MCPPackageLaunch declares how to start the fetched package. If Launch
// is nil, the resolver derives Command and Args from Origin.Type defaults
// (npm → "npx -y <id>@<ver>"; pypi → "uvx <id>==<ver>"; oci → image
// entrypoint). If Launch is set, the manifest owns Command and Args
// verbatim — no implicit identifier injection. Command may be empty only
// for oci.
type MCPPackageLaunch struct {
	Command string             `json:"command,omitempty" yaml:"command,omitempty"`
	Args    []MCPArgument      `json:"args,omitempty" yaml:"args,omitempty"`
	Env     []MCPKeyValueInput `json:"env,omitempty" yaml:"env,omitempty"`
}

// MCPArgument is one command-line argument.
type MCPArgument struct {
	Type  MCPArgumentType `json:"type" yaml:"type"`
	Name  string          `json:"name,omitempty" yaml:"name,omitempty"`
	Value string          `json:"value,omitempty" yaml:"value,omitempty"`
}

type MCPArgumentType string

const (
	MCPArgumentTypePositional MCPArgumentType = "positional"
	MCPArgumentTypeNamed      MCPArgumentType = "named"
)

// MCPKeyValueInput is one declared environment variable.
type MCPKeyValueInput struct {
	Name       string `json:"name" yaml:"name"`
	Value      string `json:"value,omitempty" yaml:"value,omitempty"`
	IsRequired bool   `json:"isRequired,omitempty" yaml:"isRequired,omitempty"`
}
