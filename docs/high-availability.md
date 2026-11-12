# Running several replicas

Every replica serves the API, the web UI and the MCP endpoint. The background controllers are different: they change things outside the registry, so exactly one replica runs them at a time.

- **Deployment controller and discovery:** create, update and remove agents and MCP servers in the runtimes, and discover what runs there.
- **Plugin and Skill controllers:** pin git sources to exact commits.

The replicas elect that one, the leader. When it stops or fails, another takes over.

## Choosing a mechanism

Set `AGENT_REGISTRY_LEADER_ELECTION`, or `leaderElection.mechanism` in the Helm chart:

| Mechanism | How it works | Needs |
| --- | --- | --- |
| `postgres` (default) | The leader holds a session advisory lock on a dedicated connection to the registry's database. Postgres releases it when that connection ends. | Nothing extra. Not behind a pooler in transaction mode (PgBouncer). |
| `kubernetes` | The leader holds and renews a `coordination.k8s.io` Lease named `leaderElection.name` in the release namespace. | RBAC on `leases`; the chart creates the Role and RoleBinding. |
| `none` | Every replica runs the controllers. | One replica. The chart refuses `replicaCount` above 1. |

All replicas must use the same mechanism: the two do not see each other. To change it on a running system, stop the old pods first, for example by scaling to one replica for the upgrade.

## What happens when

| Event | `postgres` | `kubernetes` |
| --- | --- | --- |
| A replica starts | It leads if the lock is free, after waiting `renewDeadline` | It leads if the Lease is free or expired |
| The leader shuts down (rolling upgrade) | It stops its controllers, then releases the lock; a standby leads `renewDeadline` later | It stops its controllers, then releases the Lease; a standby leads within `retryPeriod` |
| The leader's pod or node dies | Postgres notices the dead connection after about `leaseDuration` + 3 × `retryPeriod` (TCP keepalives); then as above | A standby takes over `leaseDuration` after the last renewal |
| The leader loses the database or API server | It stops its controllers within `retryPeriod` + `renewDeadline` | Same |
| The database fails over | All connections drop; the replicas elect a leader again on the new primary | No effect on the election |

A new Postgres leader waits `renewDeadline` before it starts. Postgres releases a lock the moment it ends the old leader's session (a killed backend, a restart, a failover), while the old leader notices only at its next check. The wait gives it time to stop, so two replicas never run the controllers together.

## Settings

| Setting | Chart value | Default |
| --- | --- | --- |
| `AGENT_REGISTRY_LEADER_ELECTION` | `leaderElection.mechanism` | `postgres` |
| `AGENT_REGISTRY_LEADER_ELECTION_NAME` | `leaderElection.name` | `agentregistry-controllers` |
| `AGENT_REGISTRY_LEADER_ELECTION_LEASE_DURATION` | `leaderElection.leaseDuration` | `15s` |
| `AGENT_REGISTRY_LEADER_ELECTION_RENEW_DEADLINE` | `leaderElection.renewDeadline` | `10s` |
| `AGENT_REGISTRY_LEADER_ELECTION_RETRY_PERIOD` | `leaderElection.retryPeriod` | `2s` |
| `AGENT_REGISTRY_LEADER_ELECTION_IDENTITY` | set to the pod name | host name |
| `AGENT_REGISTRY_LEADER_ELECTION_NAMESPACE` | set to the pod's namespace | the pod's namespace |

The timing must satisfy retry period < renew deadline < lease duration, so a leader always gives up before anyone can take over.

## Seeing who leads

- Logs: `became leader`, `stopped leading` and `lost leadership`, with the mechanism.
- `kubernetes`: `kubectl get lease agentregistry-controllers -o jsonpath='{.spec.holderIdentity}'`.
- `postgres`:

  ```sql
  SELECT a.client_addr, a.backend_start
  FROM pg_locks l JOIN pg_stat_activity a USING (pid)
  WHERE l.locktype = 'advisory' AND l.granted
    AND a.application_name = 'agentregistry-leader-election';
  ```

Applications embedding the registry can still supply their own leadership for the Deployment controller with `AppOptions.DeploymentControllerLeadership`; the built-in election is then off, and the Plugin and Skill controllers run on every replica as before.
