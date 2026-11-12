//go:build integration

package leader

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConnConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("AGENT_REGISTRY_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://agentregistry:agentregistry@localhost:5432/agentregistry?sslmode=disable"
	}
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	return cfg
}

func postgresFor(t *testing.T, name string) *Postgres {
	return &Postgres{ConnConfig: testConnConfig(t), Name: name, Timing: fastTiming}
}

func TestPostgresElectsOneAndHandsOver(t *testing.T) {
	name := "test-" + t.Name() + time.Now().Format("150405.000")
	var holders atomic.Int32
	a := runReplica(t, "a", postgresFor(t, name), &holders, nil)
	require.Eventually(t, a.leading.Load, 5*time.Second, 20*time.Millisecond, "the first replica leads")

	b := runReplica(t, "b", postgresFor(t, name), &holders, nil)
	time.Sleep(500 * time.Millisecond)
	assert.False(t, b.leading.Load(), "a second replica waits")

	a.stop()
	<-a.done
	require.Eventually(t, b.leading.Load, 5*time.Second, 20*time.Millisecond, "b takes over after a clean shutdown")
}

// A leader whose connection is killed stops leading, and a standby takes
// over: Postgres releases the lock with the session.
func TestPostgresLeaderLosesItsConnection(t *testing.T) {
	name := "test-" + t.Name() + time.Now().Format("150405.000")
	var holders atomic.Int32
	a := runReplica(t, "a", postgresFor(t, name), &holders, nil)
	require.Eventually(t, a.leading.Load, 5*time.Second, 20*time.Millisecond)
	b := runReplica(t, "b", postgresFor(t, name), &holders, nil)

	admin, err := pgx.ConnectConfig(context.Background(), testConnConfig(t))
	require.NoError(t, err)
	defer admin.Close(context.Background())
	var killed int
	require.NoError(t, admin.QueryRow(context.Background(), `
		SELECT count(pg_terminate_backend(a.pid))
		FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.granted
		  AND a.application_name = $1
		  AND ((l.classid::bigint << 32) | l.objid::bigint) = ($2::bigint & x'FFFFFFFFFFFFFFFF'::bigint)`,
		ApplicationName, lockKey(name)).Scan(&killed))
	require.Equal(t, 1, killed, "one connection held the lock")

	// The old term ends; then one replica leads again. Either may win: the
	// old leader reconnects and campaigns like any other replica.
	require.Eventually(t, func() bool {
		return holders.Load() == 1 && (b.leading.Load() || a.terms.Load() == 2)
	}, 10*time.Second, 20*time.Millisecond, "a new term starts; a=%v/%d b=%v/%d",
		a.leading.Load(), a.terms.Load(), b.leading.Load(), b.terms.Load())
}

func TestPostgresElectionsAreIndependentByName(t *testing.T) {
	stamp := time.Now().Format("150405.000")
	var h1, h2 atomic.Int32
	a := runReplica(t, "a", postgresFor(t, "one-"+stamp), &h1, nil)
	b := runReplica(t, "b", postgresFor(t, "two-"+stamp), &h2, nil)
	require.Eventually(t, func() bool { return a.leading.Load() && b.leading.Load() }, 5*time.Second, 20*time.Millisecond)
}
