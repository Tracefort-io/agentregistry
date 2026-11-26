# Tracing

With `tracing.enabled` (env `AGENT_REGISTRY_TRACING_OTLP=true`), the registry
exports OpenTelemetry traces over OTLP/HTTP. The exporter is configured by the
standard `OTEL_EXPORTER_OTLP_*` variables; the chart sets
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` from `tracing.endpoint`, which is used
as-is and so includes the path (for example
`http://otel-collector:4318/v1/traces`). Audit log export (`audit.otlp`) can
go to another collector.

## What is traced

| Span | Where |
|---|---|
| `agentregistry-api <route>` | Every request to the REST API and UI server, named after its route pattern once routed (`GET /v0/agents/{name}`), else its method |
| `agentregistry-mcp <route>` | Every request to the registry's MCP server |
| `agentregistry-identity-check POST` | Every agent identity check, with child spans `identity.resolve` (attributes `spiffe.id`, `identity.outcome`: `resolved`, `missing`, `mismatch`, `malformed`, `unknown`, `revoked`, `record_mismatch` or `error`, and on success `agentregistry.agent` and `agentregistry.deployment`) and `identity.history` (the identity records read, `spiffe.id.prefix`) |
| HTTP client spans | The registry's calls to the AuthZEN PDP, its access request service, the policies OPA and OpenBao |

A request that carries a W3C `traceparent` continues that trace, so the
identity check appears under agentgateway's `ExtAuthz` span and an API call
under the caller's span; the registry's calls to the PDP and OpenBao carry the
trace context on. Sampling is parent-based and samples requests without a
trace context, unless `OTEL_TRACES_SAMPLER` says otherwise.

Spans never carry tokens, certificates, credentials or request bodies. A
rejected identity is the check working and is not marked as an error; failing
to read the identity records is.

Not traced yet: database queries, and calls to Kubernetes and to other
external services.
