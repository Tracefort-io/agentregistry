package v1alpha1

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Validate runs structural validation on the MCPServer envelope.
func (m *MCPServer) Validate() error {
	var errs FieldErrors
	errs = append(errs, ValidateObjectMeta(m.Metadata)...)
	errs = append(errs, validateMCPServerSpec(&m.Spec)...)
	errs = append(errs, validateMCPCredential(m.Spec.Credential, m.Metadata.Namespace)...)
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// credentialHeaderToken is an HTTP field name (RFC 9110 token).
var credentialHeaderToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

// forbiddenCredentialHeaders would change how the request is routed, framed
// or attributed, rather than authenticate it.
var forbiddenCredentialHeaders = []string{
	"connection", "content-length", "cookie", "host", "keep-alive", "proxy-authorization",
	"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}

func validateMCPCredential(c *MCPCredential, namespace string) FieldErrors {
	var errs FieldErrors
	if c == nil {
		return errs
	}
	errs = append(errs, validateSecretKeyRef(c.SecretRef, "spec.credential.secretRef")...)
	if c.SecretRef.Key == "" {
		errs.Append("spec.credential.secretRef.key", fmt.Errorf("%w: the key holding the credential", ErrRequiredField))
	}
	if ns := c.SecretRef.Namespace; ns != "" && ns != namespaceOrDefault(namespace) {
		errs.Append("spec.credential.secretRef.namespace", fmt.Errorf("%w: the Secret must be in the MCP server's own namespace", ErrInvalidRef))
	}
	if c.Header != "" {
		if !credentialHeaderToken.MatchString(c.Header) {
			errs.Append("spec.credential.header", fmt.Errorf("%w: %q is not an HTTP header name", ErrInvalidFormat, c.Header))
		} else if slices.Contains(forbiddenCredentialHeaders, strings.ToLower(c.Header)) {
			errs.Append("spec.credential.header", fmt.Errorf("%w: %s cannot carry a credential", ErrInvalidFormat, c.Header))
		}
	}
	if c.Scheme != "" && !credentialHeaderToken.MatchString(c.Scheme) {
		errs.Append("spec.credential.scheme", fmt.Errorf("%w: %q is not an auth scheme", ErrInvalidFormat, c.Scheme))
	}
	return errs
}

func namespaceOrDefault(namespace string) string {
	if namespace == "" {
		return DefaultNamespace
	}
	return namespace
}

// validateMCPPackageName enforces the upstream MCP-ecosystem catalogue name format
// for the optional MCPPackage.ServerName field (e.g. "io.github.user/server").
// Matches the upstream modelcontextprotocol/registry server.json schema for
// the `name` field.
func validateMCPPackageName(s string) error {
	if s == "" {
		return nil // optional field
	}
	if l := len(s); l < UpstreamMCPPackageNameMinLen || l > UpstreamMCPPackageNameMaxLen {
		return fmt.Errorf("%w: serverName length must be %d-%d chars, got %d", ErrInvalidFormat, UpstreamMCPPackageNameMinLen, UpstreamMCPPackageNameMaxLen, l)
	}
	if !UpstreamMCPPackageNameRegex.MatchString(s) {
		return fmt.Errorf("%w: serverName must match upstream identifier pattern (e.g. `io.github.user/server` or `my-mcp`): %q", ErrInvalidFormat, s)
	}
	return nil
}

func validateMCPServerSpec(s *MCPServerSpec) FieldErrors {
	var errs FieldErrors
	errs.Append("spec.title", validateTitle(s.Title))
	errs.Append("spec.iconUrl", validateIconURL(s.IconURL))

	// Source (bundled) and Remote (pre-running) are the two ways to describe
	// an MCP server. Exactly one must be set.
	switch {
	case s.Source == nil && s.Remote == nil:
		errs.Append("spec", fmt.Errorf("%w: one of spec.source or spec.remote must be set", ErrRequiredField))
	case s.Source != nil && s.Remote != nil:
		errs.Append("spec", fmt.Errorf("%w: spec.source and spec.remote are mutually exclusive", ErrInvalidRef))
	case s.Source != nil:
		errs = append(errs, validateMCPServerSource(s.Source)...)
	case s.Remote != nil:
		errs = append(errs, validateMCPServerRemote(s.Remote)...)
	}

	return errs
}

func validateMCPServerRemote(t *MCPRemote) FieldErrors {
	var errs FieldErrors
	if t.Type == "" {
		errs.Append("spec.remote.type", fmt.Errorf("%w", ErrRequiredField))
	}
	if t.URL == "" {
		errs.Append("spec.remote.url", fmt.Errorf("%w", ErrRequiredField))
		return errs
	}
	if err := validateWebsiteURL(t.URL); err != nil {
		errs.Append("spec.remote.url", err)
	}
	return errs
}

func validateMCPServerSource(src *MCPServerSource) FieldErrors {
	var errs FieldErrors
	pkg := src.Package
	if pkg == nil {
		return errs
	}

	// Transport — required type, closed to {stdio, http}, plus http requires port.
	if pkg.Transport.Type == "" {
		errs.Append("spec.source.package.transport.type", fmt.Errorf("%w", ErrRequiredField))
	}
	switch pkg.Transport.Type {
	case "", "stdio", "http":
		// empty is already flagged above; stdio/http are valid
	default:
		errs.Append("spec.source.package.transport.type",
			fmt.Errorf("%w: must be one of \"stdio\" or \"http\" (got %q)", ErrInvalidRef, pkg.Transport.Type))
	}
	if pkg.Transport.Type == "http" && pkg.Transport.Port == 0 {
		errs.Append("spec.source.package.transport.port", fmt.Errorf("%w: required for http transport", ErrRequiredField))
	}

	// Origin — type, identifier, and the polymorphism invariant.
	if pkg.Origin.Type == "" {
		errs.Append("spec.source.package.origin.type", fmt.Errorf("%w", ErrRequiredField))
	}
	if pkg.Origin.Identifier == "" {
		errs.Append("spec.source.package.origin.identifier", fmt.Errorf("%w", ErrRequiredField))
	}

	errs = append(errs, validateMCPPackageOrigin(pkg.Origin)...)
	return errs
}

// validateMCPPackageOrigin enforces the discriminated-union invariant:
// exactly one of NPM/PyPI/OCI sub-structs is non-nil, matches Origin.Type,
// and carries a non-empty (and well-formed) ServerName. Per-type version
// requirements (NPM/PyPI must have Version) are enforced here; OCI's
// tag-or-digest invariant lives in the per-type validator since it
// parses Identifier.
func validateMCPPackageOrigin(o MCPPackageOrigin) FieldErrors {
	var errs FieldErrors

	// Count non-nil sub-structs — exactly one must be set.
	set := 0
	if o.NPM != nil {
		set++
	}
	if o.PyPI != nil {
		set++
	}
	if o.OCI != nil {
		set++
	}
	if set == 0 {
		errs.Append("spec.source.package.origin", fmt.Errorf("%w: one of origin.npm, origin.pypi, or origin.oci must be set", ErrRequiredField))
		return errs
	}
	if set > 1 {
		errs.Append("spec.source.package.origin", fmt.Errorf("%w: exactly one of origin.npm, origin.pypi, or origin.oci may be set", ErrInvalidRef))
		return errs
	}

	// Sub-struct must match Type discriminator.
	switch o.Type {
	case MCPPackageOriginTypeNPM:
		if o.NPM == nil {
			errs.Append("spec.source.package.origin.npm", fmt.Errorf("%w: required when origin.type is %q", ErrRequiredField, o.Type))
			return errs
		}
		if o.NPM.Version == "" {
			errs.Append("spec.source.package.origin.npm.version", fmt.Errorf("%w", ErrRequiredField))
		}
		if o.NPM.ServerName == "" {
			errs.Append("spec.source.package.origin.npm.serverName", fmt.Errorf("%w", ErrRequiredField))
		}
		if err := validateMCPPackageName(o.NPM.ServerName); err != nil {
			errs.Append("spec.source.package.origin.npm.serverName", err)
		}
	case MCPPackageOriginTypePyPI:
		if o.PyPI == nil {
			errs.Append("spec.source.package.origin.pypi", fmt.Errorf("%w: required when origin.type is %q", ErrRequiredField, o.Type))
			return errs
		}
		if o.PyPI.Version == "" {
			errs.Append("spec.source.package.origin.pypi.version", fmt.Errorf("%w", ErrRequiredField))
		}
		if o.PyPI.ServerName == "" {
			errs.Append("spec.source.package.origin.pypi.serverName", fmt.Errorf("%w", ErrRequiredField))
		}
		if err := validateMCPPackageName(o.PyPI.ServerName); err != nil {
			errs.Append("spec.source.package.origin.pypi.serverName", err)
		}
	case MCPPackageOriginTypeOCI:
		if o.OCI == nil {
			errs.Append("spec.source.package.origin.oci", fmt.Errorf("%w: required when origin.type is %q", ErrRequiredField, o.Type))
			return errs
		}
		if o.OCI.ServerName == "" {
			errs.Append("spec.source.package.origin.oci.serverName", fmt.Errorf("%w", ErrRequiredField))
		}
		if err := validateMCPPackageName(o.OCI.ServerName); err != nil {
			errs.Append("spec.source.package.origin.oci.serverName", err)
		}
	case "":
		// Already flagged as ErrRequiredField on origin.type — no further checks.
	default:
		errs.Append("spec.source.package.origin.type", fmt.Errorf("%w: unsupported origin type %q (expected one of: %q, %q, %q)", ErrInvalidRef, o.Type, MCPPackageOriginTypeNPM, MCPPackageOriginTypePyPI, MCPPackageOriginTypeOCI))
	}

	return errs
}
