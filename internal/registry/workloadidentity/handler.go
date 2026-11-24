package workloadidentity

import (
	"log/slog"
	"net/http"
)

// CheckPath is where agentgateway's external authorization calls the check.
const CheckPath = "/identity/check"

// Request headers. agentgateway sets them from what it verified: the subject
// of the agent's JWT-SVID (jwt.sub) and the SPIFFE ID of its TLS client
// certificate (source.spiffeId). Nothing the agent sends reaches the check.
const (
	HeaderTokenSubject  = "X-Identity-Token-Subject"
	HeaderCertificateID = "X-Identity-Certificate-Id"
)

// Response headers on success. agentgateway copies them onto the agent's
// request, replacing any header of the same name the agent sent.
const (
	HeaderAgent         = "X-Agentregistry-Agent"          // <namespace>/<name>:<tag>
	HeaderDeployment    = "X-Agentregistry-Deployment"     // <namespace>/<name>
	HeaderDeploymentUID = "X-Agentregistry-Deployment-Uid" // the Deployment's UID
	HeaderSPIFFEID      = "X-Agentregistry-Spiffe-Id"      // the verified SPIFFE ID
)

// ResponseHeaders are the headers the gateway must copy onto the request.
var ResponseHeaders = []string{HeaderAgent, HeaderDeployment, HeaderDeploymentUID, HeaderSPIFFEID}

// NewHandler serves the identity check at CheckPath: 200 with the resolved
// identity in ResponseHeaders, 403 for an ID that does not resolve, 503 when
// the records cannot be read. The gateway rejects the request on anything
// but 200. Responses carry no detail; the reason is logged.
func NewHandler(resolver *Resolver, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CheckPath, func(w http.ResponseWriter, r *http.Request) {
		subject, okSubject := single(r.Header, HeaderTokenSubject)
		certificate, okCertificate := single(r.Header, HeaderCertificateID)
		if !okSubject || !okCertificate {
			// Repeated headers are refused rather than picked from.
			subject, certificate = "", ""
		}
		res, err := resolver.Resolve(r.Context(), subject, certificate)
		switch {
		case err == nil:
			h := w.Header()
			h.Set(HeaderAgent, res.AgentNamespace+"/"+res.AgentName+":"+res.AgentTag)
			h.Set(HeaderDeployment, res.DeploymentNamespace+"/"+res.DeploymentName)
			h.Set(HeaderDeploymentUID, res.DeploymentUID)
			h.Set(HeaderSPIFFEID, res.SPIFFEID)
			w.WriteHeader(http.StatusOK)
		case Rejected(err):
			log.Warn("agent identity rejected", "token_subject", subject, "certificate_id", certificate, "reason", err.Error())
			w.WriteHeader(http.StatusForbidden)
		default:
			log.Error("agent identity check failed", "token_subject", subject, "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	return mux
}

// single returns the header's value when it is present exactly once.
func single(h http.Header, name string) (string, bool) {
	values := h.Values(name)
	if len(values) != 1 {
		return "", len(values) == 0
	}
	return values[0], true
}
