package authz

import (
	"context"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

const storeListerPage = 500

// StoreLister is a CandidateLister over the per-kind v1alpha1 stores.
type StoreLister struct {
	stores map[string]*v1alpha1store.Store
}

var _ CandidateLister = (*StoreLister)(nil)

// NewStoreLister wraps the stores map keyed by Kind.
func NewStoreLister(stores map[string]*v1alpha1store.Store) *StoreLister {
	return &StoreLister{stores: stores}
}

// ListIDs pages through the kind's rows, terminating ones included so
// lists that show them are filtered too, and returns up to limit distinct
// (namespace, name) keys. Tagged kinds yield one key per name.
func (l *StoreLister) ListIDs(ctx context.Context, kind, namespace string, limit int) ([]ResourceID, error) {
	store, ok := l.stores[kind]
	if !ok || store == nil {
		return nil, fmt.Errorf("no store for kind %q", kind)
	}
	seen := make(map[ResourceID]struct{})
	out := make([]ResourceID, 0)
	cursor := ""
	for {
		rows, next, err := store.List(ctx, v1alpha1store.ListOpts{
			Namespace:          namespace,
			Limit:              storeListerPage,
			Cursor:             cursor,
			IncludeTerminating: true,
		})
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", kind, err)
		}
		for _, row := range rows {
			id := ResourceID{Namespace: row.Metadata.Namespace, Name: row.Metadata.Name}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
		if next == "" {
			return out, nil
		}
		cursor = next
	}
}
