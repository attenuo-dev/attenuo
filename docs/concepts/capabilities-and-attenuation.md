# Capabilities and attenuation

A capability says what one hop of a chain may do. Attenuation is the rule that a hop can pass on only what it has, or less.

## A capability

A capability has three fields, `server`, `tool` and `constraints`, and an optional fourth, `limits`.

- `server` is the name of an MCP upstream, as mounted at `/mcp/{server}`.
- `tool` is a tool name. The proxy also treats some other MCP methods as tools, such as `resources/read` and `prompts/get`.
- `constraints` maps an argument name to a test on its value.

`server` and `tool` can be an exact name, `*`, or a prefix glob such as `read_*`.

A constraint is `{op, value}`, and `op` is one of:

- `equals`: the argument must equal a JSON value.
- `one_of`: the argument must equal one of a list of values.
- `prefix`: the argument must be a string that starts with the value.

Arguments with no constraint are free. A call that leaves out a constrained argument is denied.

Example: `github:create_issue` with `repo` prefix `acme/` lets the holder open issues only in repositories under `acme/`.

## Run limits

`limits` caps how much of a capability a delegation run may use (ADR-0010):

- `calls`: at most n allowed calls matched by the capability.
- `sum`: the total of one integer argument (an amount, say) over those calls.
- `calls_per`: at most n calls per value of one argument (per recipient, say).
- `distinct`: at most n different values of one argument. `calls_per` and `distinct` can count the host of a URL instead of the whole URL (`"derive": "host"`).

The maxima are in the signed token; what has been used is kept by the server, per hop lease. Every allowed call is charged to every matching limited capability in every hop of the chain, so a sub-agent cannot reset its parent's budget by delegating again. A call that would take any of them past its maximum is denied with `budget_exhausted` before Cedar runs, and no approval passes it. Servers older than 0.1.0 accept a `limits` block and ignore it. See [the run-limits design](../design/run-limits.md) and [Writing policies](../guides/writing-policies.md#run-limits).

## Attenuation

When a hop delegates to a child, the child's capabilities must be covered by the parent's. The rules:

1. The parent's server and tool patterns must cover the child's. `*` covers anything. `read_*` covers `read_file` and `read_*`. An exact name covers only itself, never a glob.
2. Every argument the parent constrains must also be constrained by the child. The child's test must be at least as strict. A child may add constraints the parent does not have.
3. Every limit the parent has must also be on the child, with a maximum no larger. A child may add limits. At exchange the server fills in limits the child left out and lowers the child's figures to what the parent has left.

So `repo prefix acme/` can become `repo equals acme/api`, or `repo prefix acme/api`. It cannot become a prefix that is shorter, and it cannot drop the constraint.

Each child capability must be covered by a single parent capability. A child that would be covered only by the union of two parent capabilities is rejected. This is deliberately conservative. It keeps the check simple and the reason for a refusal easy to explain.

An empty request is rejected too.

## Three things shrink together

Attenuation is not only about capabilities. On every exchange:

- the child's capabilities, run limits included, must be covered by the parent's,
- the child's expiry cannot be later than the parent's (the server clamps it for you),
- the chain depth cannot pass `max_depth`.

A request that would widen any of these fails closed.

## Checked twice

The rule is checked at issue time, when the child token is minted. It is checked again at call time, because the verifier validates the whole chain on every request. A forged or edited token cannot gain width after the fact.

## Capabilities are a ceiling, not a permission

A capability does not allow a call by itself. At call time the call must first fit a capability of the last hop. Then Cedar policy must also permit it. Deny is the default. See [Writing policies](../guides/writing-policies.md).

This is why narrow grants matter. A capability of `github:*` also covers `resources/read` and `prompts/get` on that server.

## Limits today

- Only `equals`, `one_of` and `prefix` exist. Numeric and time-range constraints are proposed, not built. A `sum` limit bounds a total over the run, not the value of one call.
- Run limits count per delegation run. Limits per time window are not built.
- Property tests (`crates/attenuo-core/tests/attenuation_props.rs`) check that coverage never lets a child permit something its parent does not, limits included. They check soundness, not that every narrower request is accepted.

More detail: [RFC-0001 section 3](../spec/rfc-0001-attenuo.md#3-delegation-chain-data-model) and [ADR-0005](../decisions/0005-policy-decision-point.md).
