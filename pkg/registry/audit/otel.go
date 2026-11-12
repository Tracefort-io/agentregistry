package audit

import (
	"context"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

// EventName names audit records in OpenTelemetry.
const EventName = "agentregistry.audit"

// OTelRecorder emits each event as an OpenTelemetry log record through
// logger, for a collector to forward to a SIEM or log store. Denials are
// warnings; everything else is info.
func OTelRecorder(logger otellog.Logger) Recorder {
	return RecorderFunc(func(ctx context.Context, e Event) {
		var r otellog.Record
		r.SetEventName(EventName)
		r.SetTimestamp(e.Time)
		r.SetObservedTimestamp(time.Now())
		r.SetSeverity(otellog.SeverityInfo)
		r.SetSeverityText("INFO")
		if e.Outcome == OutcomeDenied {
			r.SetSeverity(otellog.SeverityWarn)
			r.SetSeverityText("WARN")
		}
		r.SetBody(attribute.StringValue(summary(e)))
		r.AddAttributes(
			attribute.String("audit.action", e.Action),
			attribute.String("audit.outcome", e.Outcome),
			attribute.String("audit.detail", e.Detail),
			attribute.String("audit.resource.kind", e.Resource.Kind),
			attribute.String("audit.resource.namespace", e.Resource.Namespace),
			attribute.String("audit.resource.name", e.Resource.Name),
			attribute.String("audit.resource.tag", e.Resource.Tag),
			attribute.String("audit.source", e.Source),
			attribute.String("audit.request_id", e.RequestID),
			attribute.String("enduser.id", e.Actor.Subject),
			attribute.String("audit.actor.issuer", e.Actor.Issuer),
			attribute.String("audit.actor.username", e.Actor.Username),
			attribute.Bool("audit.actor.client", e.Actor.Client),
			attribute.String("audit.actor.via", strings.Join(e.Actor.Via, ",")),
		)
		logger.Emit(ctx, r)
	})
}

// summary is a one-line description, such as
// "alice apply Prompt default/p: success (created)".
func summary(e Event) string {
	who := e.Actor.Username
	if who == "" {
		who = e.Actor.Subject
	}
	if who == "" {
		who = "anonymous"
	}
	what := e.Resource.Kind
	if e.Resource.Name != "" {
		what += " " + e.Resource.Namespace + "/" + e.Resource.Name
	} else if e.Resource.Namespace != "" {
		what += " " + e.Resource.Namespace + "/*"
	}
	out := who + " " + e.Action + " " + what + ": " + e.Outcome
	if e.Detail != "" {
		out += " (" + e.Detail + ")"
	}
	return out
}
