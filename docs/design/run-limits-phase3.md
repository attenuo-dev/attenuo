# Run limits phase 3: design

- Status: proposed, not accepted. Step 1 of section 7 (per-user windows) is built on `feat/run-limits-phase3`, with the choices of [section 8](#choices-made-in-step-1-2026-11-06) taken in place of answers; see [run limits: as built](run-limits.md#as-built-per-user-windows-phase-3-step-1). Steps 0 and 2 to 6 stay unbuilt until the open questions below are answered.
- Date: 2026-11-06. Base: `main` at 4ffe725.
- Related: [run limits](run-limits.md) sections 2, 3.3, 3.4, 3.6, 5, 6 and 7, and open questions 4, 5, 6, 7, 8 and 9; [ADR-0010](../decisions/0010-run-limits.md); [multi-replica readiness](multi-replica.md) (the `Counters` trait and the run lock); [RFC-0001](../spec/rfc-0001-attenuo.md) sections 3.1 and 8; [related work: AgentGateway](../research/related-work.md#agentgateway-linux-foundation); [config reference: `[leases]`](../reference/config.md#leases); [injection suite](../evaluation/injection-suite.md); [AgentDojo plan](../research/agentdojo-plan-2026-11-05.md); [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md) (leases); [ADR-0009](../decisions/0009-output-labelling.md) (results recorded after the response).

The run-limits design left three things for phase 3: per-user windows across runs, mapping an RFC 9396 amount into a root limit at hop 0, and reservation. This note reads the counters, the pipeline and hop-0 intake from the code at 4ffe725, and proposes a design for each part. It also says what each part is worth given what phases 1 and 2 measured, ranks a path with sizes, and lists questions for the maintainer. It proposes no code in this change.

## 1. What was built and what phase 3 promised

Phases 1 and 2 are built and measured (#50 to #64). The run-limits note's [Status](run-limits.md#status) summarises them: "token limits `calls`, `sum`, `calls_per` and `distinct`, with URL-host destinations, narrowed per hop and charged against every ancestor; run usage as `context.usage` for soft limits in policy; refund from the admin API and the CLI; budgets on the console and in `attenuo lease tree`."

Its phase table ([section 6](run-limits.md#6-phased-plan)) gives phase 3 as:

> Per-user windows across runs (`context.usage.user_window`), RAR amount mapping at hop 0, optional reservation (`"reserve": true`).

The metric the table gives it is "utility with limits set from the task by a planner, against limits set at hop 0", on a model-in-the-loop AgentDojo adapter. That adapter exists now, but no limits arm has been run on it ([AgentDojo plan: run limits](../research/agentdojo-plan-2026-11-05.md#run-limits)).

Where each part came from:

- **Per-user windows.** [Section 3.6](run-limits.md#36-rate-per-window): "A per-user window across runs ('at most 5000 a day from this user's agents') is a real banking requirement, but it is about the user, not the delegation, and it needs a store keyed by user rather than by lease. It is phase 3 at the earliest, as a `context.usage.user_window` attribute, and open question 4." Open question 4 asks whether such windows "belong in attenuo (a user-keyed store, `context.usage.user_window`) or always at a gateway, as RFC-0001 section 8 says for rate limits". The ADR keeps them out of scope "until a later decision". RFC-0001 section 3.1 also puts "a window per run (at most n calls an hour)" in phase 3.
- **RAR mapping.** [Section 5](run-limits.md#5-interoperability): "A deployment whose IdP issues RAR details could map an amount into the root hop's `sum` limit at hop 0. That needs an agreed `type` and is open question 6."
- **Reservation.** [Section 3.3](run-limits.md#33-attenuation): reservation (escrow) "carves the child's share out of the parent at exchange time. It gives each child a guaranteed share, but strands budget in children that never spend, needs a return path when a child's lease ends or is revoked, and turns every exchange into a write against the parent's counter. Rejected for phase 1; it can be added later as `"reserve": true` without changing the call path."

## 2. Inventory

Read from the code at 4ffe725.

- Counters: `crates/attenuo-audit/src/sqlite/budgets.rs`. `counter_in` reads one row of `budget_counters`, keyed by (`lease`, `cap`, `kind`, `arg`, `value`). `charge_in` opens an `IMMEDIATE` transaction, refuses a decision id that already charged, plans every write with `budget::plan` (all or none, `Exhausted` on the first charge that does not fit), and upserts each counter and logs each charge in `budget_charges` under the decision id. `refund_in` returns what one decision logged, once (`UnknownCharge`, `ChargeRefunded`). It frees a `distinct` value only when no other unrefunded decision logged it (SR-62) and recomputes saturated usage counters from the rows left (FZ2-4). `hop_limits` keeps each issued hop's limits for display. `budget_meta` keeps the HMAC key that `calls_per` and `distinct` values are hashed under (`value_key`) and the span key.
- Run usage: it lives in the same table under the run's `chain_id`, with kinds `usage_calls`, `usage_amount` and `usage_destination` and `"<server>/<tool>"` as `arg` (`attenuo_core::limits::usage_charges`). It is charged in the same transaction as token limits, saturates at `MAX_LIMIT` (Cedar's largest `Long`) and never refuses a call. Revoking a run's root lease deletes it.
- Pipeline: `crates/attenuo-server/src/authz/pipeline.rs`. `decide_inner` takes the run guard, reads `budget_view` (matching token limits from `charges_for`, then usage charges when `usage_inputs` says the tool keeps usage), and evaluates Cedar with `CallLabels { budget, usage, .. }`. It then charges an allowed call through `LeaseStore::charge` or `charge_sync_deferred`, and drops the guard once the charge has committed. When the charge finds a counter exhausted, the decision becomes `budget_exhausted`. When the audit append fails, `refund_unrecorded` gives the charge back. Unreadable usage with no matching limit gives Cedar the worst case (`UNREADABLE_USAGE`). With a limit, it is `budget_error`.
- The SR-55 run lock: `Pipeline::run_guard` holds 64 striped `Mutex<()>` (`RUN_LOCK_STRIPES`), indexed by the first 8 hex digits of SHA-256 of the `chain_id`. It is taken only when the chain carries a limit or the tool keeps usage, and its wait is reported as `run_lock_wait_seconds`. Its doc comment says: "In process only: two servers on one store would not share it." The [multi-replica note](multi-replica.md#interfaces) cites it as `authz.rs::Pipeline::run_guard`. Since #180 it is in `authz/pipeline.rs`, unchanged.
- Budgets in Cedar: `crates/attenuo-policy/src/schema.rs::context_type` declares `budget: BudgetContext, usage: UsageContext`, with `type UsageContext = { calls: Long, amount: Long, destination_seen: Bool }`. `request.rs` builds the record, and `SCREEN_UNKNOWNS` makes `budget` and `usage` unknowns for list screening. `usage.rs::policies_read_usage` walks the loaded set for any read of `context.usage`, and `PolicyEngine::tracks_usage` uses that walk to decide whether usage is kept at all. The context also carries `originating_user: { subject, issuer, authenticated_at_unix, attributes }`.
- Token limits: `crates/attenuo-core/src/limits.rs`. `Limits { calls, sum, calls_per, distinct }` and `ArgLimit { arg, max, derive }` are both `deny_unknown_fields`, so a server that does not know a new member under `limits` refuses the token instead of ignoring the limit. `Capability` itself has no closed field list.
- Exchange clamping: `crates/attenuo-server/src/routes/token.rs::clamp_to_remaining` reads the parent hop's `calls` and `sum` counters with `budget_used`, outside any write transaction and without the run lock, and clamps the child's figures to what is left.
- Hop-0 intake: `crates/attenuo-server/src/idp/intake.rs` keeps only `authorization_details` entries whose `type` is `attenuo_capabilities` and drops every other entry without a word. `idp/claims.rs::map_id_jag` reads only `client_id` from an ID-JAG: "The draft's `resource` and `scope` claims are not used: the capabilities of the root token come from `[[root_grants]]` and the request, not from the IdP." Nothing reads `authorization_details` from the IdP credential.
- Results recorded after the response: `crates/attenuo-proxy/src/label.rs`. The proxy hands every response to an allowed mediated call to `Authorizer::record_result` before relaying it. Allowed calls are remembered in `AwaitedResults`, so an answer on the `GET` listen stream, or in the body of a later `POST` (SR-85), is still recorded. The map is bounded (`MAX_AWAITED_RESULTS` 10,000, `MAX_AWAITED_RESULTS_PER_SESSION` 256; the run holding the most calls gives up its oldest, SR-86), and entries expire after `AWAITED_RESULT_TTL` (10 minutes). List requests share the map (SR-87). A result can therefore arrive minutes after the decision, or never. AuthZEN has no result route: an external PEP's result never reaches attenuo.
- Identity in the store: Decision records carry `originating_subject` in clear (`attenuo-core/src/decision.rs`). `lease_subjects` keeps the subject of each lease in clear, for revoke by user.
- Retention: `[leases] run_state_retention_seconds` (30 days) prunes `budget_counters`, `budget_charges` and `approvals` once their leases are gone from the registry. `retention_seconds` (a week) prunes the leases first. Both run in one maintenance task (`SqliteLeaseStore::prune_run_state`, [config reference](../reference/config.md#leases)). Every prune rule is keyed to leases: a row under a key that is not a lease is kept only while a charge under it is.

## 3. Per-user windows

### 3.1 What it is

A per-user window is the usage of a destructive tool by every run of one user, over a fixed time window: allowed calls and the sum of the catalog's `amount` input. Policies read it the way they read run usage. Nothing about it is in a token.

```cedar
// At most 5000 a day from this user's agents, whatever the run or the token says.
@id("user_daily_spend_cap_5000")
forbid (principal, action == Action::"banking/send_money", resource)
when {
  context.input has amount &&
  context.usage.user_window.day.amount + context.input.amount > 5000
};
```

### 3.2 Why policy, never a token field

The token describes a delegation: what this user let this chain of agents do, narrowed per hop. A window describes the user across every delegation. A window figure in the token would be wrong in three ways:

- Each run's root token would state its own figure, and two concurrent runs of one user could state different ones. Nothing says which governs.
- P2 narrowing means nothing across runs. A child can be held under its parent's figure, but a new run starts from a new root.
- The hop that writes the figure is the one section 2 of the run-limits note warns about: a planner that has read injected content can write a generous one.

The window belongs to the deployment: the bank's daily cap, set by whoever writes the policy. This also keeps the token format unchanged.

It is a soft limit in the run-limits sense ([section 3.7](run-limits.md#37-interaction-with-approvals-and-labels)). It is a policy rule over a figure the server computes, and it denies, or asks with `@obligation("approval")`. Unlike a token limit, the store does not re-check it at charge time, so the lock of section 3.8 is what keeps it exact.

### 3.3 Windows: fixed calendar windows in UTC

**Recommendation: fixed calendar windows in UTC. Policy picks the length by the attribute it reads; the server keeps only the kinds a loaded policy reads.**

| Choice | For | Against |
|---|---|---|
| Fixed calendar window (UTC day, UTC hour) | One counter row per (user, tool, kind, window start). A refund goes back to the row it was charged to. Easy to explain ("today, in UTC") and to audit. Matches how banks state daily limits. | A burst across the boundary: up to twice the cap within a few seconds of midnight. |
| Sliding log (exact last 24 h) | No boundary burst. | One row per charged call, kept for the window length, and a sum over them on every read under the lock. Retention depends on the window length. |
| Sliding estimate (two fixed buckets, weighted) | Cheap. | Inexact by design. The figure a policy sees cannot be stated to a user or an auditor, and a refund cannot be placed. |

Kinds: `hour` and `day`. The window start is `floor(now_unix / length) * length`, computed from the same `now` the decision uses. A month is not a fixed length, and a bank's day is often local time; both are open question 2. A window per run (RFC-0001 section 3.1's "at most n calls an hour") is not proposed. A run already ends at its token's `exp`, and a per-run hourly window would add a second time base for little.

The window length comes from the policy, not the token or the config. A loaded policy that reads `context.usage.user_window.day` makes the server keep the `day` kind. One that reads `.hour` makes it keep `hour`. A set that reads neither keeps nothing, so a deployment that writes no such rule pays nothing. This extends `policies_read_usage` from "reads `context.usage`" to "reads `context.usage.user_window.<kind>`", and keeps the walk's rule of erring towards tracking. A tracking flag alone in the config would also work. Reading the policy is what phase 2 does for run usage (#60), so it is the consistent choice.

### 3.4 How it reaches Cedar

`UsageContext` gains `user_window: { hour: WindowFigures, day: WindowFigures }` with `type WindowFigures = { calls: Long, amount: Long }`. It is always present, so policies need no `has` guards, and it is per tool (`"<server>/<tool>"`), as run usage is.

It is per tool, not per capability, because a capability index is only meaningful inside one token. Across runs the same payment tool appears under different indices in different tokens.

The brief for this note named the members `{calls, sum}`. This note uses `amount` to match `context.usage.amount`, the figure it extends.

Figures are the window's usage before this call, as with run usage. A kind that is not kept reads as zero. When the store cannot read a kept window, Cedar sees the worst case (`calls` and `amount` the largest `Long`), as `UNREADABLE_USAGE` does today: a count rule refuses or asks, and an amount rule overflows into `policy_error`.

Everything that carries `usage` today carries it too: the decision record's `usage` member (as an optional `user_window` member, omitted when nothing is kept, so earlier records hash as before), `-32003` and `-32008` error data, AuthZEN answers, the admin dry run (`usage: {user_window: {day: {calls, amount}}}` taken from the request) and `attenuo policy test` cases. A PEP cannot send it, and anything under `context.usage` in an AuthZEN request is ignored, as it is today. `SCREEN_UNKNOWNS` already covers `usage` as a whole.

### 3.5 The store

```sql
-- Per-user windows (run limits phase 3). `user` is the hex HMAC-SHA-256, under `user_key`
-- in budget_meta, of the RFC 8785 JSON of [issuer, subject]; never the subject itself.
CREATE TABLE IF NOT EXISTS user_windows (
    user         TEXT    NOT NULL,
    window_kind  TEXT    NOT NULL,   -- 'hour' | 'day'
    window_start INTEGER NOT NULL,   -- Unix seconds, UTC
    tool         TEXT    NOT NULL,   -- '<server>/<tool>'
    measure      TEXT    NOT NULL,   -- 'calls' | 'amount'
    used         INTEGER NOT NULL,
    PRIMARY KEY (user, window_kind, window_start, tool, measure)
) WITHOUT ROWID;
-- What each decision charged to a window, for refunds.
CREATE TABLE IF NOT EXISTS user_window_charges (
    decision_id  TEXT    NOT NULL,
    user         TEXT    NOT NULL,
    window_kind  TEXT    NOT NULL,
    window_start INTEGER NOT NULL,
    tool         TEXT    NOT NULL,
    measure      TEXT    NOT NULL,
    amount       INTEGER NOT NULL,
    at           TEXT    NOT NULL,
    refunded_at  TEXT    NULL
);
CREATE INDEX IF NOT EXISTS user_window_charges_decision_idx ON user_window_charges(decision_id);
```

The key is (issuer, subject), not the subject alone. Two IdPs can issue the same `sub` to different people. The same person under two IdPs then has two windows, which is open question 2's business.

One alternative is to reuse `budget_counters` under a synthetic lease key such as `user:<digest>:day:<start>`, which would make `charge_in`, `refund_in` and the charge log work unchanged. It is rejected because every prune rule in `prune_run_state` is keyed to leases. A synthetic key is not a lease, so its counter would be pruned once no charge under it is left, and the charge log ages out after `run_state_retention_seconds`. An operator who set that retention below a window's length would reset open windows: the limit would fail open. A dedicated table can prune by the window's end, which is the rule that is right for it.

### 3.6 Charging and refunds

**Charging.** A window charge is a third kind of charge next to limit and usage charges. It is passed to the same `LeaseStore::charge` call and written by `charge_in` in the same `IMMEDIATE` transaction, after the policy allows. So a call's limits, its run usage and its window usage are applied together or not at all. Like run usage, a window charge saturates at `MAX_LIMIT` and never refuses a call by itself, and a charge of window usage alone does not force `synchronous=FULL`. The `sum` rule decides what `amount` adds (a non-negative integer up to 2^53; anything else adds 0). Denied calls charge nothing. An allowed call whose upstream fails is charged, for the reason [section 3.4](run-limits.md#34-enforcement-point-and-atomicity) gives.

The charge commits before the decision's audit append and is refunded if the append fails, as today. Windows inherit open question 8 of the run-limits note unchanged.

**Refund.** The operator refund (`POST /admin/budgets/refund`, `attenuo budget refund`) returns a decision's window charges along with its other charges, once, to the window each was charged to. A refund after that window has closed restores nothing that can still be spent. The answer's `refunded` keeps counting token-limit counters only, as it does for usage. A decision that charged only window usage cannot occur, because every destructive call that keeps a window also keeps run usage.

**Revocation does not reset a window.** Revoking a run's root lease deletes its run usage today. It must not touch `user_windows`, or "revoke the run, start a new one" would reset the user's daily spend.

**Durability.** A window that guards money is lost the way any usage counter is: at `durability = "normal"`, a power failure can drop the newest commits, and a lost charge can be spent again in the same window. When a call also charges a `sum` limit, it already commits with a full sync. Otherwise the deploy guide should say that a deployment relying on a window for money runs at `durability = "full"`.

### 3.7 Retention

A window row is prunable once its window ended longer ago than a retention period. That should be its own key, `[leases] user_window_retention_seconds`, defaulting to 35 days, enough for a month's refunds after the longest window. It must be at least the longest kind's length (one day), and the server should refuse a shorter value at start rather than reset open windows. A charge row goes when its window row goes. A refund after that answers 410 `charge_pruned` for the window part, as a pruned run-state charge does today. The pass joins the existing maintenance task, after the run-state pass, under the same `maintenance_batch_rows` and `maintenance_max_passes`, and its deletions are counted in `run_state_pruned_total{kind="user_window"}`.

Size: one row per (user, tool, kind, window, measure). A user active every hour on one payment tool, with both kinds kept, writes about 50 rows a day; at 35 days that is about 1,750 rows per user and tool. The rows are small. The cost is an index lookup per call, not disk.

### 3.8 The run lock does not cover a window

The SR-55 lock serialises one run's budgeted decisions, from the read of the figures to the charge, so that a rule over `context.usage` sees what the run's earlier calls charged. A window spans runs. Two runs of one user hold different run stripes, both read the same window figure, and both pass a rule meant to stop the second. That is SR-55 again, one level up.

**Proposal: a second set of stripes keyed by the user digest, taken after the run stripe, only by calls that keep a window.** Always taking the run lock first and the user lock second, from separate arrays, cannot deadlock. No code path holds a user stripe while waiting for a run stripe, and one array never has two of its stripes held by one decision. Using one array for both would let a decision whose run and user hash to the same stripe block on itself, since `std::sync::Mutex` is not reentrant. The wait is reported in the existing `run_lock_wait_seconds`, or in a `user_lock_wait_seconds` next to it.

What it costs: every budgeted decision of one user is serialised across that user's runs, for the time of one Cedar evaluation (12 to 163 microseconds, README "Policy stage") plus the charge. That is fine for a person's agents. For a service account that runs hundreds of concurrent runs as one subject, it is a measurable queue (open question 3).

Across replicas this is the multi-replica note's step 4 generalised. Its proposed `Counters::lock_run(chain_id)` becomes a lock on a key that is either a run or a user:

```rust
pub enum LockKey<'a> { Run(&'a str), User(&'a str) }

pub trait Counters: Send + Sync {
    // budget_used, charge, charge_sync_deferred, refund, budget_summary: as in multi-replica.md
    /// Serialise the budgeted decisions of `keys`, acquired in the order given (runs before users).
    fn lock(&self, keys: &[LockKey<'_>]) -> Result<CounterGuard<'_>, AuditError>;
}
```

In process, `lock` takes today's run stripes and the new user stripes. In Postgres, it takes two `pg_advisory_xact_lock` calls in the same order, in one transaction held from the read to the charge. This proposal does not contradict the multi-replica note. It adds one row to its inventory, a per-process lock that a second replica would not share, and the window table joins the "run limit counters" row: safe on one shared file, split per file.

With one file per replica (that note's shape (b) against copies), each replica keeps its own windows, and a user gets the cap once per replica. A window is therefore only as exact as the deployment's store. Until the `Counters` trait and a shared store exist, a window is a single-replica guarantee, like soft limits over run usage (multi-replica open question 5).

### 3.9 Privacy and the console

The table keys users by a keyed digest. The key is `user_key`, a new random key in `budget_meta`, separate from `value_key` so that a recipient hash and a user hash can never be compared. As the module doc of `attenuo-audit/src/budget.rs` says of `value_key`, the key lives in the same store, so the digest keeps subjects off the window rows, not out of reach of someone who holds the whole file and a list of guesses.

The rest of the store already holds subjects in clear: every decision record's `originating_subject`, and `lease_subjects`. The digest therefore protects a copy of the window table (a debugging extract, an export) and keeps it from becoming a per-user activity ledger that outlives the leases. It does not hide users from the operator, who has the audit log.

What the console and admin API show:

- The lease page of a run shows the run's user's window figures for the tools the run used: the kind, the window start in UTC, `calls` and `amount`. The server computes the digest from the chain's originating user. Nothing the client sends picks the user.
- `GET /admin/users/windows?issuer=…&subject=…` returns one user's current windows, behind the admin token. The server digests the pair. There is no route that lists every user's windows, since a list of digests is useless to the operator and a list of subjects would rebuild what the digest avoids.
- `attenuo lease tree` shows the same figures under the root node.

## 4. RAR mapping at hop 0

### 4.1 Two sources, two trust levels

[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) `authorization_details` can reach hop 0 from two places:

1. **The hop-0 request body.** The agent sends it, as it sends `attenuo_capabilities` today. A `limits` block mapped from it only narrows, since adding a limit never widens a capability, so it is safe in P2 terms. But it is the agent's statement, not the user's. And an agent can already send `limits` inside `attenuo_capabilities` today. Mapping from the request buys interoperability with clients that speak a RAR payment `type`, and nothing else.
2. **The IdP credential.** An ID-JAG or ID token that carries `authorization_details` the user consented to, signed by the IdP. This is the case that matters: the figure is the user's own statement, set at hop 0, which section 2 of the run-limits note names as where budgets help most. Today attenuo reads nothing but `client_id` from an ID-JAG (`claims::map_id_jag`). Whether any IdP puts `authorization_details` in an ID-JAG or ID token was not verified for this note, and no deployment of attenuo is known to have one (open question 4).

The proposal maps both, and records which source each mapped limit came from. When the credential carries a mapped entry, an entry of the same `type` for the same tool in the request is refused, so the agent cannot replace the user's figure with its own.

### 4.2 The mapping

The mapping is configuration per IdP, not a fixed `type`. RFC 9396 leaves the meaning of each `type` to the deployment, and the run-limits note's open question 6 asks which `type` to use. Configuration answers that per deployment:

```toml
[[idps.rar]]
# Which entries: their `type`, and the one tool they limit.
type = "payment_initiation"
tool = "banking/send_money"
# `sum` from an amount. `from` is a JSON pointer into the entry. The amount is a decimal
# string or number in major units, converted to minor units with `exponent`, in one currency.
sum = { arg = "amount", from = "/instructedAmount/amount", currency_from = "/instructedAmount/currency", currency = "EUR", exponent = 2 }
# A recipient list becomes a pin and a per-recipient count: `one_of` on `arg`, and `calls_per` 1.
recipients = { arg = "recipient", from = "/creditorAccount/iban" }
```

What an entry of a configured `type` becomes, on the one requested capability for `tool`:

- `sum = { arg, max }`, where `max` is the amount in minor units. RFC 9396's payment example gives the amount as a decimal string next to a currency (from the RFC's section 2 example; not re-checked for this note). `sum` takes non-negative integers only, so the mapping converts with the configured exponent and refuses rather than rounds (run-limits open question 5).
- From a recipient value or list: the constraint `{"op": "one_of", "value": [...]}` on `arg`, plus `calls_per: {arg, max: 1}`. The pin says who may be paid, and the count says each of them once. Without the pin, `calls_per` alone would let any recipient be paid once.
- The mapped capability is then attenuated against `[[root_grants]]` like any request. A root grant with its own `sum` clamps the mapped figure down, as `attenuate_with` clamps today. A user who consented to 5000 under a grant of 2000 gets 2000, which is narrower and so allowed.

### 4.3 What is refused

Anything the mapping cannot read exactly is refused at intake with `invalid_request` and the sub-code `invalid_authorization_details`, the error RFC 9396 defines. It is never ignored, because ignoring a restriction the user stated would widen the grant:

- An amount that is not a decimal string or number, is negative, has more fraction digits than `exponent`, or exceeds `MAX_LIMIT` in minor units.
- A currency other than the configured one, or a missing currency when `currency_from` is set.
- No requested capability for the entry's `tool`, or more than one. Two capabilities would each carry their own `sum`, so the user's figure would be spent twice.
- Two entries of one `type` for one tool. Whether that is one budget or two is not knowable from the entries.
- An empty recipient list, or a recipient that is not a string.
- An entry that carries RFC 9396's common fields (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) or any member the mapping does not name. The deployment's mapping does not say what those restrict, and dropping them would widen.

Entries of a `type` the deployment did not configure stay ignored, as today.

### 4.4 Input only

The mapping runs once, at hop 0, and produces an ordinary `limits` block and constraint. Nothing downstream knows that RAR was involved. The token format, the narrowing rules, the charge path and every verifier stay as they are. The `token.root` audit record gains the digest and source (`request` or `credential`) of each mapped entry, so an auditor can tell a user-stated figure from an agent-stated one. The token response carries no `authorization_details`.

## 5. Reservation

### 5.1 Two readings

"Reservation" has two readings, and the brief for this note and the run-limits note use different ones.

- **Escrow at exchange (A).** This is what section 3.3 and the ADR's considered option describe: "a child's share is carved out of the parent's counter at exchange". `"reserve": true` on a child's limit moves the child's `max` out of what the parent has left, so siblings cannot spend it.
- **Hold at decision, settled on the result (B).** This is the brief's reading. A call reserves its amount when it is allowed, and the reservation is settled when its result is recorded.

Both matter only for `sum` (and in principle `calls`). `calls_per` and `distinct` have no single remaining figure to carve; exchange clamps them to the parent's `max`, not to what is left (run-limits [as built: phase 1](run-limits.md#as-built-phase-1)).

### 5.2 Escrow at exchange (A)

The token side is a member under `limits`: `"limits": {"sum": {"arg": "amount", "max": 200}, "reserve": true}`. `Limits` is `deny_unknown_fields`, so an older server refuses such a token instead of treating it as unreserved: it fails closed, as `distinct` did.

At exchange, the child's `calls` and `sum` figures are charged against the parent hop and every ancestor of the parent, in one `IMMEDIATE` transaction, under the exchange's id, as a reservation. When any ancestor lacks the room, the exchange clamps to what is left, as today, but inside the write transaction. Today's `clamp_to_remaining` reads outside any transaction and without the run lock, and with escrow that read would be a race. A reservation of zero is refused.

The call path changes, contrary to section 3.3's "without changing the call path". A call by the reserving child, or by its descendants, charges the hops from the reserving child down, and stops there. The reservation has already charged the reserving child's parent and every hop above it, so charging those again would count the spend twice. `charges_for` needs to know where reservations sit, which the token now says.

Release returns what the child did not spend (`max - used`) to the parent and every ancestor, logged like a refund. The release must not happen at lease expiry. An expired lease can still be renewed while its token is valid ([deploy guide](../guides/deploying.md#leases-tuning-the-interval)), so releasing at expiry would let a renewed child spend a share the parent has already reused. Release happens when the child's lease is revoked (final), or once the hop's `expires_at` has passed (after which nothing can renew it). The maintenance task sweeps for both. A share therefore stays stranded for up to the child token's lifetime: the cost section 3.3 named.

### 5.3 Hold at decision, settled on the result (B)

At decision time the summed argument is already known, and today's charge is exactly that amount. A hold differs from a charge only if the settled amount can differ from the argument. That happens when the upstream reports the amount taken: a fee, a conversion, a partial fill, or "at most 500" with the price decided upstream.

Settlement depends on the recorded result, and that runs into three facts:

- **A result is upstream output.** Settling down from a result is a refund that the upstream controls. A hostile server (A3) reports 0 and gets its budget back. That is run-limits open question 7 (`refund_on_error`) under another name, and section 3.4's reason for counting failed calls applies: the proxy cannot tell whether the effect happened.
- **A result can arrive late or never.** It can arrive on the listen stream or in a later `POST` (SR-85) up to `AWAITED_RESULT_TTL` (10 minutes) after the decision, or be evicted (SR-86), or never come. A missing result cannot release the hold, because the call was forwarded and its effect may have happened. So a hold with no result settles at the full amount, which is today's charge.
- **AuthZEN has no result route.** On an external PEP every hold settles at the full amount.

So B adds something only for upstreams whose results are trusted to report a lower amount. It needs a per-tool catalog opt-in naming the result field, which may only settle down, never up, with the result in the same `tool_result` record. Without that, B is today's behaviour with more state. The note recommends not building B, and folding it into run-limits open question 7.

### 5.4 Interaction with refunds and late results

- An operator refund of a decision under an escrowed child returns the amount to the child's counter, not to the parent: the share stays reserved for the child until it is released. A refund after release returns it to the parent and its ancestors, which the release log makes exact.
- Revoking a reserving child releases its share at once. Revoking the run's root releases nothing that matters, since the run is over.
- Results recorded after the response (A, or B without trusted settlement) change no counter. Only an operator changes a charge after the decision.

## 6. What each part is worth

From the measurements in [run-limits section 7](run-limits.md#7-measured) and the AgentDojo runs:

- **Per-user windows cannot be measured on either suite.** Each injection-suite case is one run with no time dimension (ADR-0010: "the corpus has no time dimension to measure it on"). The AgentDojo adapter gives every benchmark run a new root token, so that "taint and limits can't leak between runs" ([plan](../research/agentdojo-plan-2026-11-05.md#how-attenuo-goes-between-the-agent-and-the-tools)). Nothing in either suite repeats a user across runs. Windows are a deployment requirement (a bank's daily cap), not a measured defence. Their benign cost is the same as a run-level soft limit: section 7's measured "a uniform hard count loses benign multi-call work" applies to a window set too low, and nothing tells an operator the right daily figure except their own business.
- **Windows extend a denial of service.** Section 2 of the run-limits note says an injected agent can spend a run's budget on junk, which "costs the user the task, not integrity; the fix is a new delegation". Against a window, a new delegation does not help: the user's agents stay refused until the window rolls over, or an operator refunds call by call. The AgentDojo runs show that injected text already denies service through model refusals (on Opus 5.5, 91 of 140 workspace runs under one attack, [four models](../research/agentdojo-plan-2026-11-05.md#four-models-on-one-sample-2026-11-05)), and that the attack success rate hides it. A hard window turns a one-run denial into a day-long one. A window rule that asks (`@obligation("approval")`) rather than denies keeps the user's other runs going, at the cost of depending on the approver. The note recommends the asking form as the documented default for windows, and the deny form for a regulated cap.
- **RAR mapping is the one way to get a user-stated figure, and nobody issues one.** Per-task figures are what worked: given the figure each task states, `attenuo_task_limits` refuses 8 of the 15 dev attack calls `attenuo` allows and loses 1 of 130 benign calls, against 10 lost to a uniform `calls: 1` ([per-task figures](run-limits.md#per-task-figures)). Of the two refusals that do not depend on call order, one is `banking-04`'s amount under `sum: 10`, exactly what an `instructedAmount` would state. But those figures were written by the same agent family after reading the cases, and the mapping is only worth more than an agent-supplied `limits` block if an IdP signs the details. It cannot be measured until a client or IdP sends them. The AgentDojo banking catalog's float `amount` ([plan](../research/agentdojo-plan-2026-11-05.md#replay-on-all-suites)) also means no `sum` arm runs there without the decimal rule of section 4.2.
- **Reservation has no measured case.** It matters only for `sum` and `calls`, and only with concurrent siblings under one limited parent. The suite has no concurrent siblings. No case shows a benign sibling refused because another spent the parent's budget first, the cost overbooking was accepted for. Escrow's own cost, budget stranded for a child token's lifetime, is certain. Its benefit is unmeasured.

## 7. Proposed path

Ranked so that the cheapest step that could change the decision comes first, and the parts with no measured value come last.

| Step | What | Crates | Effort |
|---|---|---|---|
| 0 | Measure before building, where anything can be measured: a sibling-overbooking case (two concurrent sub-agents under one `sum`) in the injection suite, to see whether overbooking refuses benign work; and the AgentDojo limits arm the plan already describes, with per-task figures, as phase 3's own metric. | `evaluation/` only | S |
| 1 | Per-user windows: the `user_windows` and `user_window_charges` tables and `user_key`; window charges in `charge_in` and refunds in `refund_in` (SQLite and memory stores); `UsageContext::user_window` in the schema, request and screen; tracking by `context.usage.user_window.<kind>` reads; the user stripes after the run stripe; worst case when unreadable; the record, error data, AuthZEN and dry-run members; `policy test` cases; the retention key and prune pass; refusing a retention below a day. | attenuo-audit (`sqlite/schema.rs`, `sqlite/budgets.rs`, `sqlite/leases.rs`, `budget.rs`, `lease.rs`), attenuo-core (`limits.rs`, `decision.rs`), attenuo-policy (`schema.rs`, `request.rs`, `usage.rs`, `testing.rs`), attenuo-server (`authz/pipeline.rs`, `authz/budgets.rs`, `authz/usage.rs`, `config.rs`, `routes/admin.rs`, `metrics.rs`), docs | M |
| 2 | Windows on the console, `GET /admin/users/windows` and `attenuo lease tree`. | attenuo-server (`admin_ui.rs`, `routes/admin.rs`), attenuo-cli | S |
| 3 | The user lock in `Counters::lock`, as part of the multi-replica note's step 4, not before it. | attenuo-audit, attenuo-server (`authz/pipeline.rs`) | S on top of that step |
| 4 | RAR mapping from the credential and the request: `[[idps.rar]]`, the decimal conversion, the refusals of section 4.3, the source in `token.root`. Only once a client or IdP sends details. | attenuo-server (`idp/intake.rs`, `idp/claims.rs`, `config.rs`), docs | S to M |
| 5 | Escrow at exchange (`"reserve": true`): the token member and its narrowing rule; reservation charges in the exchange's transaction; `charges_for` stopping at a reserving hop; release on revoke and after `expires_at`; the console. Only if step 0 shows overbooking refusing benign work. | attenuo-core (`limits.rs`, `capability.rs`), attenuo-audit, attenuo-server (`routes/token.rs`, `authz/pipeline.rs`, maintenance), both SDKs, docs | M to L |
| 6 | Hold at decision (B): not proposed. It becomes a per-tool trusted-settlement opt-in if run-limits open question 7 is answered yes. | | |

Step 1 stands on its own for a single replica and should not wait for the multi-replica work, provided the deploy guide states the single-replica limit plainly, as it does for soft limits today. Steps 4 and 5 should wait for demand.

## 8. Open questions

1. **Does phase 3 belong in attenuo?** RFC-0001 section 8 puts "routing, rate limits, OTel and tool federation" at gateways, and AgentGateway ships rate limiting ([related work](../research/related-work.md#agentgateway-linux-foundation)). A per-user window over a tool's amount argument is closer to an authorization fact than a request rate: it needs the catalog's `amount`, the decision and the refund, which a gateway does not have. Does the maintainer accept that, and add one sentence to section 8 (attenuo keeps per-user usage of destructive tools for policy; request rates stay at the gateway)? Or should windows stay at the gateway, and this note close at RAR and reservation?
2. **Window kinds and time zone.** `hour` and `day` in UTC only, or also a calendar month, or a configured offset or time zone for "the bank's day"? Should one user under two IdPs be one window (needs an identity link nobody has) or two?
3. **Wait for `Counters`?** Build the window store and the user stripe now for one replica, or only as part of the multi-replica note's `Counters` trait, so that windows are never a per-process guarantee? And is serialising every budgeted decision of a user acceptable for service accounts that run many concurrent runs as one subject?
4. **IdP cooperation.** The useful source of a RAR figure is the IdP credential, and no IdP attenuo integrates with is known to sign `authorization_details` into an ID-JAG or ID token. Map from the request now for interoperability, from the credential only once an IdP does it, or not at all until a deployment asks?
5. **Which reservation, if any.** Escrow at exchange (section 5.2), which the run-limits note promised, or hold at decision (section 5.3), which this note's brief described and which reduces to trusted settlement? And if escrow, is a share stranded for the child token's lifetime acceptable?
6. **Deny or ask by default.** Should the documented window rule ask (keeping other runs going under an injected agent that spends the window) or deny (a regulated cap the approver cannot pass)?
7. **Measure first.** Should step 0 run before any phase 3 code, given that no part of phase 3 has a measured benefit on the suites as they are?

### Choices made in step 1 (2026-11-06)

Step 1 was built before the questions above were answered. Where this note recommends an option, step 1 takes it; where it recommends none, the choice below was made for step 1 and is open to reversal.

1. Belongs in attenuo: built in attenuo, for policy over destructive tools' calls and amounts; request rates stay at the gateway. RFC-0001 section 8 is not changed: that sentence is the maintainer's.
2. Window kinds and time zone: fixed calendar windows in UTC, kinds `hour` and `day` only; no month, no configured offset. One user under two IdPs is two windows (the key is issuer and subject).
3. Wait for `Counters`: no; built for one replica, with the user stripes in process, and the deploy guide says windows are a single-replica guarantee. Serialising a user's budgeted decisions is accepted, including for service accounts; the user lock's wait is reported in the existing `run_lock_wait_seconds`, not a new series.
4. IdP cooperation (RAR): not part of step 1; nothing decided.
5. Which reservation: not part of step 1; nothing decided.
6. Deny or ask by default: ask is the documented default form (`config/policies/user-windows.cedar`, the policy guide), deny for a regulated cap, as section 6 recommends.
7. Measure first: step 1 was built without step 0, which is still open; nothing in step 1 changes what the suites can measure (section 6).
8. Tracking (section 3.3): windows are kept per kind only when a loaded policy reads `context.usage.user_window.<kind>`; there is no config flag.
9. Unreadable store (section 3.4): the worst case, both figures the largest `Long`, for every kept kind, with a diagnostic; the call is not refused for the read error itself.
10. Retention (section 3.7): `[leases] user_window_retention_seconds`, default 35 days after a window ends; values from 1 to 86399 (below a day) refused at start; 0 keeps every window, like the other retention keys. An open window is never pruned at any setting.
11. Reporting (section 3.4): the decision record names only kept kinds, with each window's `start`; error data, AuthZEN answers and the dry run carry `user_window` only when it is not all zero, so their shape is unchanged for deployments without windows.
12. Refund of a pruned window (section 3.7): when the charge log has nothing left and the record carries `usage.user_window`, 410 `charge_pruned`; a refund whose other charges remain returns them and skips the pruned window silently.
