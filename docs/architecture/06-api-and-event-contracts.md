# 06 — API and Event Contracts

The contracts in `api/` are the source of truth. This document defines the conventions and the v1 surface, with representative excerpts. Full specs are written in milestone order.

## 1. REST conventions (all services)

| Concern | Convention |
|---|---|
| Base | `https://<gateway>/api/v1/<domain>/...` where domain ∈ `core`, `cloud`, `vpn`, `netguard`, `lab`, `ai` |
| Spec | OpenAPI **3.1**, one file per domain, bundled for the gateway and codegen |
| Auth | `Authorization: Bearer <JWT>`. Project selection via `X-PF-Project: <project_id>` (or path for admin APIs) |
| Media | `application/json`; errors `application/problem+json` (RFC 9457) |
| IDs | UUIDv7 strings. Resource names are DNS-label-like (`^[a-z][a-z0-9-]{0,62}$`) |
| Time | RFC 3339 UTC (`2026-11-10T18:59:00Z`) |
| Pagination | Cursor-based: `?limit=50&cursor=<opaque>` → `{"items":[...], "next_cursor":"..."}`. Max limit 200 |
| Filtering / sorting | Explicit query params per resource (`?state=RUNNING&kind=vm&sort=-created_at`). No generic query language |
| Idempotency | `Idempotency-Key` header **required** on every POST that creates something. Stored 24 h; a replay returns the original response |
| Async | Long operations return `202 Accepted` + `Operation` + `Location: /api/v1/cloud/operations/{id}` |
| Concurrency | Mutable resources expose `ETag: "<generation>"`. `PATCH`/`PUT` require `If-Match`, else `428`. Mismatch → `412` |
| Rate limits | `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` headers; `429` with `Retry-After` |
| Deprecation | `Deprecation` + `Sunset` headers; breaking changes only in `/v2` |
| Tracing | `traceparent` accepted and propagated; `X-Request-ID` echoed |

### 1.1 Error shape

```json
{
  "type": "https://parallelf.dev/problems/quota-exceeded",
  "title": "Project quota exceeded",
  "status": 422,
  "detail": "Requested 2048 MiB memory; 1024 MiB remaining in project 'lab'.",
  "instance": "/api/v1/cloud/workloads",
  "request_id": "01937c1e-6f1a-7b4e-9a51-0c9f5d2b8e11",
  "errors": [{"field": "flavor", "code": "quota.memory"}]
}
```

Problem types are a closed catalogue in `api/openapi/components/problems.yaml` (validation, not-found, conflict, quota-exceeded, unschedulable, precondition-failed, mfa-required, step-up-required, scope-violation, rate-limited, …).

### 1.2 `Operation`

```json
{
  "id": "0193...", "kind": "workload.create", "status": "running",
  "resource": {"type": "workload", "id": "0193..."},
  "created_at": "...", "updated_at": "...", "error": null
}
```

## 2. Endpoint catalogue (v1)

### `core`

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/core/auth/login` | public (rate-limited) | password → `mfa_required` challenge or tokens |
| POST | `/core/auth/mfa/verify` | challenge | TOTP or WebAuthn assertion |
| POST | `/core/auth/refresh` | refresh token | rotation, reuse detection |
| POST | `/core/auth/logout` | session | revokes session family |
| POST | `/core/auth/step-up` | session | refreshes `auth_time` with MFA |
| POST | `/core/oauth/token` | mTLS client cert | client-credentials for service accounts |
| GET | `/.well-known/jwks.json` | public | |
| GET/POST/DELETE | `/core/mfa/factors` | self | enrol TOTP / WebAuthn |
| GET/POST | `/core/projects` · GET/PATCH `/core/projects/{id}` | `core.projects.*` | |
| GET/POST/DELETE | `/core/projects/{id}/members` | `core.members.*` | role bindings |
| GET/POST/DELETE | `/core/service-accounts` | `core.serviceaccounts.*` | |
| GET/POST/DELETE | `/core/api-tokens` | self | secret shown once |
| GET | `/core/audit` | `core.audit.read` | filters: actor, action, resource, time |
| POST | `/core/audit/verify` | `core.audit.read` | chain verification over a range |

### `cloud`

| Method | Path | Permission |
|---|---|---|
| GET/POST | `/cloud/workloads` | `cloud.workloads.read/create` |
| GET/PATCH/DELETE | `/cloud/workloads/{id}` | read/update/delete (PATCH changes `desired_state`, ssh keys, labels) |
| POST | `/cloud/workloads/{id}:start` · `:stop` · `:reboot` | `cloud.workloads.operate` |
| GET | `/cloud/workloads/{id}/events` | read |
| POST | `/cloud/workloads/{id}/console-ticket` | `cloud.workloads.console` (VMs) |
| GET/POST/DELETE | `/cloud/networks`, `/cloud/networks/{id}` | `cloud.networks.*` |
| GET | `/cloud/networks/{id}/ips` | read |
| GET/POST/DELETE | `/cloud/images` (POST = import by URL + sha256) | `cloud.images.*` |
| GET | `/cloud/flavors` | read |
| GET/POST/DELETE | `/cloud/volumes`, POST `/cloud/volumes/{id}:attach` · `:detach` | `cloud.volumes.*` |
| GET | `/cloud/nodes`, `/cloud/nodes/{id}` · POST `:drain` · `:cordon` | `cloud.nodes.*` (admin) |
| POST | `/cloud/nodes/bootstrap-tokens` | owner/admin |
| GET | `/cloud/operations/{id}` | read |
| GET/PUT | `/cloud/quotas` | admin |

### `vpn`

| Method | Path | Permission |
|---|---|---|
| GET/POST | `/vpn/devices` (POST body carries `public_key`) | `vpn.devices.read/create` |
| GET/PATCH/DELETE | `/vpn/devices/{id}` | update name/groups; DELETE = revoke |
| POST | `/vpn/devices/{id}:activate` (`ttl`) | `vpn.devices.activate` + **MFA ≤ 15 min** |
| POST | `/vpn/devices/{id}:deactivate` | `vpn.devices.activate` |
| GET | `/vpn/devices/{id}/config-template` | config without private key (client fills it in) |
| GET | `/vpn/devices/{id}/stats?from&to` | read |
| GET/POST/PATCH/DELETE | `/vpn/groups`, `/vpn/policies` | `vpn.policies.*` |
| POST | `/vpn/policies:simulate` (`device_id`, `dst`, `port`, `proto`) | read; returns matching policy + verdict |
| GET | `/vpn/gateways`, `/vpn/gateways/{id}` | admin |
| POST | `/vpn/enrolment-tokens` | admin (for `pfctl vpn enroll` on headless devices) |

### `netguard`

| Method | Path | Permission |
|---|---|---|
| GET/POST/PATCH | `/netguard/sites`, `/netguard/scopes` (POST requires `authorization_note`) | `netguard.scopes.*` (owner/admin) |
| POST | `/netguard/scopes/{id}/scan-jobs` | `netguard.scans.run` |
| GET | `/netguard/sensors` | read |
| GET/PATCH | `/netguard/assets`, `/netguard/assets/{id}` (PATCH: `authorized_state`, notes) | `netguard.assets.*` |
| GET | `/netguard/topology?site&from&to&level=l2\|l3\|flow` | read |
| GET | `/netguard/flows?src_ip&dst_ip&dst_port&community_id&from&to&limit` | `netguard.telemetry.read` |
| GET | `/netguard/dns`, `/netguard/http`, `/netguard/tls` (same filter style) | `netguard.telemetry.read` |
| GET/PATCH | `/netguard/alerts`, `/netguard/alerts/{id}` (status, notes) | `netguard.alerts.*` |
| GET/POST/PATCH | `/netguard/incidents`, `/netguard/incidents/{id}` | `netguard.incidents.*` |
| POST | `/netguard/incidents/{id}/alerts` · `/timeline` · `/evidence` | `netguard.incidents.update` |
| GET | `/netguard/evidence/{id}` (metadata + verified hash) | read |
| GET/POST/DELETE | `/netguard/suppressions` | `netguard.alerts.manage` |

### `lab`

| Method | Path | Permission |
|---|---|---|
| GET/POST | `/lab/targets` (register artifact + sha256 + attestation) | `lab.targets.*` |
| GET | `/lab/templates` | read |
| GET/POST/DELETE | `/lab/environments`, POST `/lab/environments/{id}:extend` (≤ max TTL) | `lab.environments.*` |
| GET | `/lab/environments/{id}/isolation-check` | runs the egress test suite and returns results |
| GET/POST/PATCH | `/lab/experiments`, `/lab/experiments/{id}/findings` | `lab.experiments.*` |
| GET | `/lab/integrity-reports?environment&session&player&from&to` | read |

### `ai`

| Method | Path | Permission |
|---|---|---|
| POST | `/ai/investigations` (`incident_id` or `alert_id`, `depth`) | `ai.investigations.create` |
| GET | `/ai/investigations/{id}` (+ `/steps`) | read |
| POST | `/ai/investigations/{id}:cancel` | create |
| GET | `/ai/reports/{id}` | read |
| POST | `/ai/reports/{id}:approve` → attaches to incident | `netguard.incidents.update` |
| GET | `/ai/budget` | read |

### Gateway

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/events/stream?types=cloud.workload.*,vpn.device.*` | SSE, RBAC-filtered projection |
| GET (WS) | `/api/v1/cloud/workloads/{id}/console?ticket=…` | single-use ticket |
| GET | `/api/v1/openapi.yaml` | bundled spec |

### 2.1 OpenAPI excerpt

```yaml
# api/openapi/cloud.yaml (excerpt)
paths:
  /cloud/workloads:
    post:
      operationId: createWorkload
      tags: [workloads]
      security: [{ bearerAuth: [] }]
      x-pf-permission: cloud.workloads.create
      parameters:
        - $ref: './components/params.yaml#/IdempotencyKey'
        - $ref: './components/params.yaml#/ProjectHeader'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/WorkloadCreate' }
      responses:
        '202':
          description: Accepted; poll the operation or subscribe to events.
          headers:
            Location: { schema: { type: string } }
          content:
            application/json:
              schema: { $ref: './components/schemas.yaml#/Operation' }
        '409': { $ref: './components/problems.yaml#/Conflict' }
        '422': { $ref: './components/problems.yaml#/Unprocessable' }
components:
  schemas:
    WorkloadCreate:
      type: object
      additionalProperties: false
      required: [name, kind, flavor, image, networks]
      properties:
        name:     { type: string, pattern: '^[a-z][a-z0-9-]{0,62}$' }
        kind:     { type: string, enum: [vm, container] }
        flavor:   { type: string, examples: [pf.small] }
        image:    { type: string, description: Image ID or name }
        networks: { type: array, minItems: 1, maxItems: 4, items: { type: string, format: uuid } }
        ssh_authorized_keys: { type: array, maxItems: 10, items: { type: string, maxLength: 4096 } }
        user_data: { type: string, maxLength: 65536, description: cloud-init (VM only) }
        env:      { type: object, maxProperties: 64, additionalProperties: { type: string, maxLength: 4096 } }
        restart_policy: { type: string, enum: [always, on-failure, never], default: always }
        labels:   { type: object, maxProperties: 32, additionalProperties: { type: string, maxLength: 63 } }
```

## 3. Event contracts

### 3.1 Envelope: CloudEvents 1.0 in NATS headers

The **payload is the bare Protobuf message** encoded as protojson (JSON) in v1 for debuggability. Metadata travels in NATS headers using the CloudEvents NATS protocol binding:

| Header | Example | Required |
|---|---|---|
| `ce-specversion` | `1.0` | yes |
| `ce-id` | `0193...` (UUIDv7, also `Nats-Msg-Id`) | yes |
| `ce-source` | `/parallelf/cloud/pf-cloudd` | yes |
| `ce-type` | `parallelf.cloud.v1.WorkloadStateChanged` | yes |
| `ce-time` | `2026-11-10T18:59:00Z` | yes |
| `ce-subject` | `workload/0193...` | yes |
| `ce-pfproject` | project UUID (extension attribute) | when scoped |
| `ce-pfschemaversion` | `1` | yes |
| `content-type` | `application/json` (protojson); `application/protobuf` reserved | yes |
| `traceparent` | W3C trace context | yes |
| `Nats-Msg-Id` | = `ce-id` | yes (JetStream dedupe) |

### 3.2 Subject naming

```text
pf.<domain>.evt.<entity>.<action>            domain events        (JetStream)
pf.<domain>.<agentkind>.<id>.status|stats    agent reports        (JetStream)
pf.<domain>.<agentkind>.<id>.desired|poke    control ↔ agent      (core NATS request/reply)
pf.ng.tel.<sensor_id>.<log_type>             telemetry            (JetStream)
pf.ng.alert.candidate                        detector output      (JetStream)
pf.lab.integrity.<environment_id>            lab relay output     (JetStream)
pf.audit.<source>                            audit events         (JetStream)
pf.dlq.<stream>                              dead letters         (JetStream)
```

Tokens are lower-case. IDs are canonical UUID strings (dashes are valid in NATS subject tokens; dots never appear in IDs). Wildcards are used only by consumers, never in publish subjects.

### 3.3 Event catalogue (v1)

| Type (`ce-type`) | Subject | Producer | Key fields |
|---|---|---|---|
| `parallelf.cloud.v1.WorkloadCreated` | `pf.cloud.evt.workload.created` | cloudd | workload, project, kind, spec digest |
| `parallelf.cloud.v1.WorkloadScheduled` | `pf.cloud.evt.workload.scheduled` | cloudd | workload, node |
| `parallelf.cloud.v1.WorkloadStateChanged` | `pf.cloud.evt.workload.state_changed` | cloudd | from, to, generation, ips[], reason |
| `parallelf.cloud.v1.WorkloadDeleted` | `pf.cloud.evt.workload.deleted` | cloudd | workload, released IPs |
| `parallelf.cloud.v1.NetworkChanged` | `pf.cloud.evt.network.{created,deleted}` | cloudd | network, cidr, kind |
| `parallelf.cloud.v1.NodeStatusChanged` | `pf.cloud.evt.node.status_changed` | cloudd | node, from, to |
| `parallelf.cloud.v1.WorkloadStatusReport` | `pf.cloud.node.<id>.status` | node-agent | workload, observed_generation, state, ips, error |
| `parallelf.vpn.v1.DeviceChanged` | `pf.vpn.evt.device.{created,enrolled,revoked,expired}` | vpnd | device, owner, tunnel_ip |
| `parallelf.vpn.v1.ActivationChanged` | `pf.vpn.evt.activation.{started,ended}` | vpnd / wg-agent | device, expires_at, reason |
| `parallelf.vpn.v1.PeerConnectivity` | `pf.vpn.evt.peer.{connected,disconnected,endpoint_changed}` | wg-agent | device, endpoint, handshake_at |
| `parallelf.vpn.v1.PeerStatsBatch` | `pf.vpn.gw.<id>.stats` | wg-agent | samples[] |
| `parallelf.netguard.v1.TelemetryRecord` | `pf.ng.tel.<sensor>.<type>` | shipper/discovery | see below |
| `parallelf.netguard.v1.AlertCandidate` | `pf.ng.alert.candidate` | ng-detect | detector, severity, dedupe_key, evidence_refs |
| `parallelf.netguard.v1.AlertChanged` | `pf.ng.evt.alert.{opened,updated,closed}` | netguardd | alert summary |
| `parallelf.netguard.v1.IncidentChanged` | `pf.ng.evt.incident.{opened,updated,resolved}` | netguardd | incident summary |
| `parallelf.lab.v1.EnvironmentChanged` | `pf.lab.evt.environment.{ready,destroyed,isolation_failed}` | labd | env, workloads |
| `parallelf.lab.v1.IntegrityReport` | `pf.lab.integrity.<env>` | lab relay | session, player, check, score |
| `parallelf.ai.v1.InvestigationChanged` | `pf.ai.evt.investigation.{started,completed,failed}` | aid | investigation, report status, cost |
| `parallelf.audit.v1.AuditEvent` | `pf.audit.<source>` | everyone | actor, action, resource, outcome |

### 3.4 Protobuf excerpts

```protobuf
// api/proto/parallelf/cloud/v1/agent.proto
syntax = "proto3";
package parallelf.cloud.v1;
import "google/protobuf/timestamp.proto";

message DesiredNodeState {
  string node_id = 1;
  int64 revision = 2;                       // monotonic; agent logs drift per revision
  repeated DesiredWorkload workloads = 3;
  repeated DesiredNetwork networks = 4;
  google.protobuf.Timestamp generated_at = 5;
}

message DesiredWorkload {
  string workload_id = 1;
  int64 generation = 2;
  WorkloadKind kind = 3;
  DesiredPower power = 4;                   // RUNNING | STOPPED | ABSENT
  Resources resources = 5;
  ImageRef image = 6;                       // digest-pinned
  repeated Nic nics = 7;                    // network_id, ip, mac
  bytes cloud_init_seed = 8;                // VM only; rendered by cloudd, size-capped
  map<string, string> env = 9;              // container only
  RestartPolicy restart = 10;
}

message WorkloadStatusReport {
  string node_id = 1;
  string workload_id = 2;
  int64 observed_generation = 3;
  WorkloadState state = 4;
  repeated string ips = 5;
  string error = 6;
  google.protobuf.Timestamp observed_at = 7;
}
```

```protobuf
// api/proto/parallelf/netguard/v1/telemetry.proto
syntax = "proto3";
package parallelf.netguard.v1;
import "google/protobuf/timestamp.proto";

message TelemetryRecord {
  string id = 1;                            // UUIDv7 assigned by shipper
  string sensor_id = 2;
  SourceTool source_tool = 3;               // ZEEK | SURICATA | DISCOVERY | PROBE | LAB_RELAY
  string log_type = 4;                      // conn, dns, http, ssl, dhcp, alert, discovery …
  google.protobuf.Timestamp observed_at = 5;
  bytes raw_sha256 = 6;                     // provenance of original line
  string community_id = 7;
  oneof body {
    Flow flow = 10;
    DnsEvent dns = 11;
    HttpEvent http = 12;
    TlsEvent tls = 13;
    DhcpEvent dhcp = 14;
    IdsAlert ids_alert = 15;
    DiscoveryResult discovery = 16;
  }
}

message Flow {
  string src_ip = 1; uint32 src_port = 2;
  string dst_ip = 3; uint32 dst_port = 4;
  uint32 proto = 5;  string app_proto = 6;
  google.protobuf.Timestamp start = 7; double duration_s = 8;
  uint64 bytes_orig = 9; uint64 bytes_resp = 10;
  uint64 pkts_orig = 11; uint64 pkts_resp = 12;
  string conn_state = 13; string zeek_uid = 14;
}
```

```protobuf
// api/proto/parallelf/netguard/v1/scope.proto
message ScanScope {
  string scope_id = 1;
  repeated string cidrs = 2;                // RFC1918/ULA/CGNAT only; agent re-checks
  repeated Technique techniques = 3;        // ARP, ICMP_ECHO, TCP_CONNECT, PASSIVE
  repeated uint32 tcp_ports = 4;            // ≤ 32 ports
  uint32 rate_pps = 5;                      // ≤ 200
  google.protobuf.Timestamp valid_until = 6;
  string authorized_by = 7;
}
message SignedScanScope {
  bytes scope = 1;                          // deterministic proto encoding of ScanScope
  bytes signature = 2;                      // Ed25519 over `scope`
  string key_id = 3;
}
```

### 3.5 JetStream stream configuration (dev defaults)

| Stream | Storage | Retention | Max age | Max bytes | Dup window | Discard |
|---|---|---|---|---|---|---|
| `PF_AUDIT` | file | limits | 30 d | 1 GiB | 2 h | old (alerted at 80%) |
| `PF_CLOUD_EVENTS`, `PF_VPN_EVENTS`, `PF_NG_EVENTS`, `PF_LAB`, `PF_AI_EVENTS` | file | limits | 7 d | 256 MiB each | 2 h | old |
| `PF_AGENT_STATUS` | file | limits | 1 h | 64 MiB | 2 m | old |
| `PF_VPN_STATS` | file | limits | 6 h | 128 MiB | 2 m | old |
| `PF_NG_TELEMETRY` | file | limits | 24 h | **2 GiB** | 2 m | **new** (publisher sees backpressure) |
| `PF_NG_ALERTS` | file | limits | 7 d | 128 MiB | 10 m | old |
| `PF_DLQ` | file | limits | 30 d | 256 MiB | — | old |

KV buckets: `pf_heartbeats` (max age 30 s), `pf_leases` (leader leases for components without Postgres access, such as multiple shippers on one host).

Consumers are durable pull consumers with explicit ack, `AckWait` 30 s, `MaxDeliver` 5, backoff `[1s, 5s, 30s, 2m]`, and `MaxAckPending` tuned per consumer (ingest: 5,000).

## 4. Compatibility rules

1. Proto: never reuse field numbers; mark removed fields `reserved`; new fields are optional; `buf breaking --against main` in CI with `FILE` compatibility.
2. REST: additive changes only within `/v1`; `oasdiff breaking` in CI.
3. Consumers **must ignore unknown fields** (protojson `DiscardUnknown: true`) and unknown event types.
4. Changing an event's meaning requires a new `ce-type` (`…v2.WorkloadStateChanged`). Producers dual-publish during migration.
5. `ce-pfschemaversion` increments on additive payload changes, so consumers can feature-gate.
