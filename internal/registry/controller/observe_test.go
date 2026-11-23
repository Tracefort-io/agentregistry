package controller

import (
	"testing"
	"time"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

func TestConditionsChanged(t *testing.T) {
	ready := func(status v1alpha1.ConditionStatus, reason, message string) v1alpha1.Condition {
		return v1alpha1.Condition{Type: "Ready", Status: status, Reason: reason, Message: message}
	}
	earlier := ready(v1alpha1.ConditionTrue, "Available", "2/2 replicas available")
	earlier.LastTransitionTime = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		current  []v1alpha1.Condition
		observed []v1alpha1.Condition
		want     bool
	}{
		{"nothing observed", []v1alpha1.Condition{earlier}, nil, false},
		{"same condition, other transition time", []v1alpha1.Condition{earlier},
			[]v1alpha1.Condition{ready(v1alpha1.ConditionTrue, "Available", "2/2 replicas available")}, false},
		{"status changed", []v1alpha1.Condition{earlier},
			[]v1alpha1.Condition{ready(v1alpha1.ConditionFalse, "Unavailable", "0/2 replicas available")}, true},
		{"reason changed", []v1alpha1.Condition{earlier},
			[]v1alpha1.Condition{ready(v1alpha1.ConditionTrue, "Completed", "2/2 replicas available")}, true},
		{"message changed", []v1alpha1.Condition{earlier},
			[]v1alpha1.Condition{ready(v1alpha1.ConditionTrue, "Available", "1/2 replicas available")}, true},
		{"new condition type", []v1alpha1.Condition{earlier},
			[]v1alpha1.Condition{{Type: "Progressing", Status: v1alpha1.ConditionFalse, Reason: "Complete"}}, true},
		{"no current conditions", nil, []v1alpha1.Condition{earlier}, true},
		{"other current conditions are ignored", []v1alpha1.Condition{earlier, {Type: "Degraded", Status: v1alpha1.ConditionTrue}},
			[]v1alpha1.Condition{ready(v1alpha1.ConditionTrue, "Available", "2/2 replicas available")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conditionsChanged(tt.current, tt.observed); got != tt.want {
				t.Errorf("conditionsChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}
