package leader

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplicationName marks the election connection in pg_stat_activity.
const ApplicationName = "agentregistry-leader-election"

// Postgres elects a leader with a session advisory lock: the replica whose
// connection holds the lock leads. Postgres releases the lock when that
// connection ends, however it ends, so a crashed leader is replaced.
//
// The lock lives on a dedicated connection, never a pooled one, so it
// cannot be released or carried off by unrelated work. It does not work
// through a connection pooler in transaction mode (such as PgBouncer).
type Postgres struct {
	// ConnConfig is copied to open the election connection.
	ConnConfig *pgx.ConnConfig
	// Name selects the lock; replicas with the same name compete.
	Name   string
	Timing Timing
}

// Run campaigns until ctx ends.
func (p *Postgres) Run(ctx context.Context, lead func(term context.Context)) {
	key := lockKey(p.Name)
	for ctx.Err() == nil {
		conn, err := p.connect(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("leader election: cannot connect to Postgres", "error", err, "retry_after", p.Timing.RetryPeriod)
				sleep(ctx, p.Timing.RetryPeriod)
			}
			continue
		}
		p.campaign(ctx, conn, key, lead)
		// Closing the connection releases the lock if it is still held.
		closeCtx, cancel := context.WithTimeout(context.Background(), p.Timing.RetryPeriod)
		_ = conn.Close(closeCtx)
		cancel()
	}
}

// connect opens the election connection. TCP keepalives make Postgres
// notice a vanished leader (and release its lock) about LeaseDuration after
// it goes silent; by then the leader, which checks its connection every
// RetryPeriod, has stopped leading.
func (p *Postgres) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg := p.ConnConfig.Copy()
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["application_name"] = ApplicationName
	cfg.RuntimeParams["tcp_keepalives_idle"] = seconds(p.Timing.LeaseDuration)
	cfg.RuntimeParams["tcp_keepalives_interval"] = seconds(p.Timing.RetryPeriod)
	cfg.RuntimeParams["tcp_keepalives_count"] = "3"
	connectCtx, cancel := context.WithTimeout(ctx, p.Timing.RenewDeadline)
	defer cancel()
	conn, err := pgx.ConnectConfig(connectCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

// campaign tries for the lock until it leads or the connection fails. After
// a term it returns, so Run reconnects: a connection that failed a check
// may be dead, and a fresh one is the only sure way to know what is held.
func (p *Postgres) campaign(ctx context.Context, conn *pgx.Conn, key int64, lead func(context.Context)) {
	for ctx.Err() == nil {
		acquired, err := p.tryLock(ctx, conn, key)
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("leader election: lock attempt failed", "error", err)
			}
			return
		}
		if !acquired {
			if !sleep(ctx, p.Timing.RetryPeriod) {
				return
			}
			continue
		}

		// Postgres releases the lock as soon as it ends the old leader's
		// session (a killed backend, a database restart or failover), but
		// that leader only notices at its next check. Hold the lock for
		// RenewDeadline before leading, so it has stopped by then.
		logger.Info("acquired leadership lock; waiting for any previous leader to stop", "election", p.Name, "wait", p.Timing.RenewDeadline.String())
		if !sleep(ctx, p.Timing.RenewDeadline) {
			p.unlock(conn, key)
			return
		}
		pingCtx, cancelPing := context.WithTimeout(ctx, p.Timing.RenewDeadline)
		err = conn.Ping(pingCtx)
		cancelPing()
		if err != nil {
			return // the lock went with the connection
		}

		logger.Info("became leader", "election", p.Name, "mechanism", "postgres")
		lost := p.leadTerm(ctx, conn, lead)
		switch {
		case ctx.Err() != nil:
			p.unlock(conn, key)
			logger.Info("stopped leading: shutting down", "election", p.Name)
		case lost:
			logger.Warn("lost leadership: election connection failed", "election", p.Name)
		default:
			// lead returned on its own; let another replica have a turn.
			p.unlock(conn, key)
			logger.Info("stopped leading", "election", p.Name)
			sleep(ctx, p.Timing.RetryPeriod)
		}
		return
	}
}

// leadTerm runs lead while the connection stays healthy, and reports
// whether it ended because a check failed.
func (p *Postgres) leadTerm(ctx context.Context, conn *pgx.Conn, lead func(context.Context)) (lost bool) {
	term, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		lead(term)
	}()
	for sleep(term, p.Timing.RetryPeriod) {
		checkCtx, cancelCheck := context.WithTimeout(term, p.Timing.RenewDeadline)
		err := conn.Ping(checkCtx)
		cancelCheck()
		if err != nil && term.Err() == nil {
			lost = true
			break
		}
	}
	cancel()
	<-done
	return lost
}

func (p *Postgres) tryLock(ctx context.Context, conn *pgx.Conn, key int64) (bool, error) {
	lockCtx, cancel := context.WithTimeout(ctx, p.Timing.RenewDeadline)
	defer cancel()
	var acquired bool
	if err := conn.QueryRow(lockCtx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired); err != nil {
		return false, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}
	return acquired, nil
}

func (p *Postgres) unlock(conn *pgx.Conn, key int64) {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timing.RetryPeriod)
	defer cancel()
	var released bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", key).Scan(&released); err != nil && !errors.Is(err, context.Canceled) {
		// Closing the connection releases it anyway.
		logger.Warn("leader election: unlock failed", "error", err)
	}
}

// seconds formats d as whole seconds, at least 1.
func seconds(d time.Duration) string {
	return strconv.Itoa(max(int(d/time.Second), 1))
}
