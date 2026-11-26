package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// withRecorder installs a recording tracer provider and the W3C propagator,
// as Init does, and restores the globals afterwards.
func withRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		// Back to no-ops, as before Init.
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
	return recorder
}

const callerTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestInitDisabledInstallsNothing(t *testing.T) {
	before := otel.GetTracerProvider()
	shutdown, err := Init(context.Background(), false, "test")
	require.NoError(t, err)
	require.NoError(t, shutdown(context.Background()))
	assert.Equal(t, before, otel.GetTracerProvider())
}

func TestHandlerContinuesTheCallersTraceAndNamesTheRoute(t *testing.T) {
	recorder := withRecorder(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/agents/{name}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/v0/agents/credit", nil)
	req.Header.Set("traceparent", callerTraceparent)
	Handler("agentregistry-api", mux).ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "agentregistry-api GET /v0/agents/{name}", span.Name(), "named after the route, not the path")
	assert.Equal(t, trace.SpanKindServer, span.SpanKind())
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", span.SpanContext().TraceID().String(), "the caller's trace")
	assert.Equal(t, "00f067aa0ba902b7", span.Parent().SpanID().String(), "a child of the caller's span")
}

func TestHandlerWithoutRouteUsesTheMethod(t *testing.T) {
	recorder := withRecorder(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	Handler("agentregistry-identity-check", h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/identity/check", nil))
	require.Len(t, recorder.Ended(), 1)
	assert.Equal(t, "agentregistry-identity-check POST", recorder.Ended()[0].Name())
}

func TestTransportSendsTheTraceContext(t *testing.T) {
	recorder := withRecorder(t)
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: Transport(nil)}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	parent.End()

	require.NotEmpty(t, received, "the request carries traceparent")
	assert.Contains(t, received, parent.SpanContext().TraceID().String(), "in the caller's trace")
	var client sdktrace.ReadOnlySpan
	for _, s := range recorder.Ended() {
		if s.SpanKind() == trace.SpanKindClient {
			client = s
		}
	}
	require.NotNil(t, client, "a client span for the call")
	assert.Equal(t, parent.SpanContext().SpanID(), client.Parent().SpanID())
}

func TestNoopUntilInit(t *testing.T) {
	// Without Init the globals are no-ops: nothing recorded, nothing sent.
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("traceparent")
	}))
	defer upstream.Close()
	resp, err := (&http.Client{Transport: Transport(nil)}).Get(upstream.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Empty(t, received)
}
