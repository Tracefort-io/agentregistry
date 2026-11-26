// Package tracing exports the registry's traces over OTLP/HTTP and joins the
// traces its callers started: agentgateway's identity check calls and REST
// API requests arrive with a W3C traceparent, and the registry's own calls to
// the PDP, OpenBao and other in-cluster services carry it on.
//
// Until Init enables it, the global OpenTelemetry tracer provider and
// propagator are no-ops, so Handler and Transport record and send nothing.
// Spans never carry tokens, credentials or request bodies.
package tracing

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
)

var logger = logging.New("tracing")

// ServiceName is the service.name of the registry's spans.
const ServiceName = "agentregistry"

// instrumentation names the registry's own spans.
const instrumentation = "github.com/agentregistry-dev/agentregistry"

// Init turns tracing on when enabled: spans are batched and exported over
// OTLP/HTTP, configured by the standard OTEL_EXPORTER_OTLP_* variables (for
// example OTEL_EXPORTER_OTLP_TRACES_ENDPOINT), and the W3C trace context
// propagator reads and writes traceparent. Sampling follows the caller's
// decision and samples requests without one (parent-based, always on),
// unless OTEL_TRACES_SAMPLER says otherwise. The returned function flushes
// and stops the exporter.
func Init(ctx context.Context, enabled bool, version string) (func(context.Context) error, error) {
	if !enabled {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName(ServiceName), semconv.ServiceVersion(version))),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	logger.Info("traces exported over OTLP")
	return provider.Shutdown, nil
}

// Handler traces every request h serves, as a server span named after the
// server and, once routed, the route pattern; it continues the caller's
// trace when the request carries one.
func Handler(server string, h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, server, otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
		if r.Pattern != "" {
			return operation + " " + r.Pattern
		}
		return operation + " " + r.Method
	}))
}

// Transport traces every request sent through base (http.DefaultTransport
// when nil), as a client span, and sends the trace context with it.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// Tracer returns the tracer for the registry's own spans.
func Tracer() trace.Tracer {
	return otel.Tracer(instrumentation)
}
