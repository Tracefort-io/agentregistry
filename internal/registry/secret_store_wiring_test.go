package registry

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// memStore is an in-memory payload store.
type memStore struct {
	mu       sync.Mutex
	data     map[string]map[string][]byte
	failPuts bool
	failGets int // the first failGets reads fail, as an unreachable store's do
	deletes  int
}

func newMemStore() *memStore { return &memStore{data: map[string]map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, ns, name string, data map[string][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPuts {
		return errors.New("store down")
	}
	m.data[ns+"/"+name] = data
	return nil
}

func (m *memStore) Get(_ context.Context, ns, name string) (map[string][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failGets > 0 {
		m.failGets--
		return nil, errors.New("connection refused")
	}
	d, ok := m.data[ns+"/"+name]
	if !ok {
		return nil, secret.ErrPayloadNotFound
	}
	return d, nil
}

func (m *memStore) Delete(_ context.Context, ns, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	delete(m.data, ns+"/"+name)
	return nil
}

// pagedSecrets lists Secret metadata two rows at a time.
type pagedSecrets struct{ refs [][2]string }

func (p pagedSecrets) List(_ context.Context, opts v1alpha1store.ListOpts) ([]*v1alpha1.RawObject, string, error) {
	start := 0
	if opts.Cursor != "" {
		start, _ = strconv.Atoi(opts.Cursor)
	}
	end := min(start+2, len(p.refs))
	var rows []*v1alpha1.RawObject
	for _, r := range p.refs[start:end] {
		rows = append(rows, &v1alpha1.RawObject{Metadata: v1alpha1.ObjectMeta{Namespace: r[0], Name: r[1]}})
	}
	next := ""
	if end < len(p.refs) {
		next = strconv.Itoa(end)
	}
	return rows, next, nil
}

func TestMigrateSecretPayloads(t *testing.T) {
	ctx := context.Background()
	from, to := newMemStore(), newMemStore()
	from.data["team/a"] = map[string][]byte{"k": []byte("a")}
	from.data["team/b"] = map[string][]byte{"k": []byte("b")}
	from.data["other/c"] = map[string][]byte{"k": []byte("c")}
	to.data["other/c"] = map[string][]byte{"k": []byte("already there, newer")}
	secrets := pagedSecrets{refs: [][2]string{{"team", "a"}, {"team", "b"}, {"other", "c"}, {"team", "no-payload"}, {"team", "z"}}}
	from.data["team/z"] = map[string][]byte{"k": []byte("z")}

	res, err := migrateSecretPayloads(ctx, secrets, from, to)
	require.NoError(t, err)
	assert.Equal(t, migrationResult{Copied: 3, Present: 1, Missing: 1}, res, "across three pages")
	assert.Equal(t, []byte("a"), to.data["team/a"]["k"])
	assert.Equal(t, []byte("already there, newer"), to.data["other/c"]["k"], "never overwrites the target")
	assert.Len(t, from.data, 4, "originals stay")
	assert.Zero(t, from.deletes)

	res, err = migrateSecretPayloads(ctx, secrets, from, to)
	require.NoError(t, err)
	assert.Equal(t, migrationResult{Present: 4, Missing: 1}, res, "running again copies nothing")
}

func TestMigrateSecretPayloadsReportsFailures(t *testing.T) {
	from, to := newMemStore(), newMemStore()
	from.data["team/a"] = map[string][]byte{"k": []byte("a")}
	to.failPuts = true
	res, err := migrateSecretPayloads(context.Background(), pagedSecrets{refs: [][2]string{{"team", "a"}}}, from, to)
	require.NoError(t, err)
	assert.Equal(t, migrationResult{Failed: 1}, res)
	assert.Contains(t, from.data, "team/a")
}

func TestMigrateSecretPayloadsUntilDoneRetriesFailures(t *testing.T) {
	from, to := newMemStore(), newMemStore()
	refs := [][2]string{{"team", "a"}, {"team", "b"}, {"team", "c"}}
	for _, r := range refs {
		from.data[r[0]+"/"+r[1]] = map[string][]byte{"k": []byte(r[1])}
	}
	// The target refuses the first two reads: the first pass fails a and b
	// and copies c; the second copies a and b and finds c present.
	to.failGets = 2

	res, err := migrateSecretPayloadsUntilDone(context.Background(), pagedSecrets{refs: refs}, from, to, time.Millisecond, time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, migrationResult{Copied: 2, Present: 1}, res)
	for _, r := range refs {
		assert.Equal(t, []byte(r[1]), to.data[r[0]+"/"+r[1]]["k"])
	}
	assert.Zero(t, from.deletes)
}

func TestMigrateSecretPayloadsUntilDoneStopsWithContext(t *testing.T) {
	from, to := newMemStore(), newMemStore()
	from.data["team/a"] = map[string][]byte{"k": []byte("a")}
	to.failPuts = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	res, err := migrateSecretPayloadsUntilDone(ctx, pagedSecrets{refs: [][2]string{{"team", "a"}}}, from, to, time.Millisecond, 10*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, migrationResult{Failed: 1}, res)
}
