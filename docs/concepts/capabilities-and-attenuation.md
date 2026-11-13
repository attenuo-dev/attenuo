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
- `path_prefix`: the argument must be a path at or below the value, compared one `/` segment at a time. A value with `..` or `.` segments is refused (see below).
- `range`: the argument must be an integer between `min` and `max`, both inclusive. The value is `{"min": 0, "max": 2000}`; either bound can be left out, but not both, and `min` cannot be greater than `max`.

An argument has at most one constraint, so kinds do not combine: "between 1 and 100 but not 13" is a Cedar rule. Arguments with no constraint are free. A call that leaves out a constrained argument is denied.

A `range` reads the argument the way Cedar does: a JSON integer, or a float with no fractional part (`5.0` is `5`). A fraction, a numeric string such as `"5"`, or a number too large for a Cedar `long` is outside every range, so the call is denied.

Example: `github:create_issue` with `repo` prefix `acme/` lets the holder open issues only in repositories under `acme/`.

### Prefixes of strings and of paths

`prefix` compares strings, character by character. That is right for URL prefixes (`https://api.example.com/v2/`), ids and names (`ticket-`, `acme/`). It is wrong for file paths: `prefix: "/workspace/"` admits `/workspace/../etc/passwd`, which a file system opens as `/etc/passwd`, and `prefix: "/workspace"` admits `/workspace-secrets/x`.

For a file path use `path_prefix`. It splits the value and its own path on `/` and requires the path's segments to be the first segments of the value, so `path_prefix: "/workspace"` admits `/workspace`, `/workspace/` and `/workspace/src/main.rs`, and refuses `/workspace-secrets/x`. It refuses, and never tries to clean up, any value that holds:

- a `.` or `..` segment (`/workspace/../etc/passwd`, `/workspace/./a`),
- an empty segment (`/workspace//a`),
- a backslash, which Windows and URL parsers read as a separator,
- a control character (NUL, tab, line breaks),
- a percent-encoded `.`, `/` or `\` (`%2e`, `%2f`, `%5c`, in either case), which a tool that decodes would read as one,
- a percent escape that is itself encoded (`%25` and two hex digits, such as `%252e`), which a tool that decodes twice would read as `.`, `/` or `\`,
- a character that Unicode compatibility normalisation (NFKC) or Windows "best fit" conversion turns into `.`, `/` or `\`: `․` `‥` `…` `︙` `︰` `﹒` `﹨` `．` `／` `＼` (U+2024, U+2025, U+2026, U+FE19, U+FE30, U+FE52, U+FE68, U+FF0E, U+FF0F, U+FF3C) and the slashes `⁄` `∕` `⧸` (U+2044, U+2215, U+29F8).

`path_prefix` reads ASCII separators after at most one percent-decode and does not normalise Unicode, so it refuses these spellings rather than guess what a tool makes of them. Other non-ASCII names (`café.txt`, `日本語/文書.md`) and a plain `%` (`50%.txt`, `100%25.txt`) are admitted. Code-page specific mappings beyond the list (a yen sign read as `\` on a Japanese Windows code page, for one) are not modelled: for such a tool, grant a narrower path.

A trailing `/` on the value is ignored. A trailing `/` on the constraint's path asks for something below it: `path_prefix: "/workspace/"` admits `/workspace/` and `/workspace/a`, but not `/workspace` itself. An absolute path (one starting with `/`) admits only absolute values and a relative one (`docs`) only relative values. The constraint's own path must follow the same rules: `path_prefix: "/workspace/../x"` or an empty path is refused when the token, the exchange request or the config is read.

`path_prefix` compares the text of the path. It does not look at the file system, so it does not see symbolic links: if `/workspace/docs` is a link to `/home/user/.ssh`, `path_prefix: "/workspace/"` admits `/workspace/docs/id_ed25519`, and the tool opens the file the link points to. A link can get there in ordinary ways, such as a cloned repository that contains one, or another granted tool that can create links. Attenuo cannot check this, because the file system is the upstream's. Pair `path_prefix` with an upstream that resolves the real path and checks it against its own allowed directories (the reference MCP filesystem server does this), or do not grant tools that can create links or check out untrusted content under the prefix.

Every value `path_prefix: P` admits also starts with `P` as a string, so swapping a path argument's `prefix` for a `path_prefix` with the same text always narrows. `path_prefix` is for paths, not URIs: `file:///public/` holds `//` and admits nothing; keep `prefix` for a URI.

`attenuo policy lint --config`, the server at startup (for `[[root_grants]]`) and `attenuo token root` / `token exchange` (for `--cap`) warn about a `prefix` constraint on an argument that looks like a path: one named `path`, `file`, `filename`, `dir`, `directory` or `folder`, or ending in `_path`, `_dir` or `_file`, or a prefix that starts with `/`, `./` or `~`. It is a warning; nothing is refused.

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
3. Every limit the parent has must also be on the child, over the same argument (and `derive`), with a maximum no larger; a child `calls` limit no larger than a parent's `calls_per` or `distinct` maximum also satisfies it. A child may add limits. At exchange the server fills in limits the child left out and lowers the child's figures to what the parent has left.

So `repo prefix acme/` can become `repo equals acme/api`, or `repo prefix acme/api`. It cannot become a prefix that is shorter, and it cannot drop the constraint.

For `path_prefix`, the child's path must lie at or below the parent's, segment by segment: `/workspace` can become `/workspace/src`, `/workspace/` or `equals /workspace/a.txt`, but not `/workspace-old` or `/`. Under a parent `/workspace/` a child `/workspace` is refused, since it admits `/workspace` itself. A `prefix` can become a `path_prefix` whose path starts with the prefix (`prefix /workspace/` to `path_prefix /workspace/src`). A `path_prefix` can never become a `prefix`, which would let `..` back in.

For `range`, the child's interval must sit inside the parent's: `0..2000` can become `10..500`, `equals 300` or `one_of [100, 200]`, but not `0..5000`, `-10..2000` or a range with the upper bound left out. A range can become an `equals` or a `one_of` only when it holds one integer (`7..7` covers `equals 7`). A `range` never covers a `prefix` or a `path_prefix`, nor the other way round.

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

- The constraint kinds are `equals`, `one_of`, `prefix`, `path_prefix` and `range`. A `range` bounds the value of each call; a `sum` limit bounds the total over the run. Use both to say "at most 2000 per payment and 5000 in all". Time-range constraints are not built ([RFC-0001 section 3.1](../spec/rfc-0001-attenuo.md#31-not-yet-implemented--proposed) says why).
- Run limits in a token count per delegation run. A user's use of destructive tools across all their runs in the current UTC hour and day is a policy input (`context.usage.user_window`, single replica only; see [run limits: per-user windows](../design/run-limits.md#as-built-per-user-windows-phase-3-step-1)); a token limit per time window is not built.
- Property tests (`crates/attenuo-core/tests/attenuation_props.rs`) check that coverage never lets a child permit something its parent does not, limits included. They check soundness, not that every narrower request is accepted.
- A Lean model of the covering rule has a machine-checked proof of the same soundness property, and that in a valid chain every hop permits what the last hop permits ([Lean proof](../design/lean-proof.md)). The proof is about the model; the Rust code is checked by the property tests above.

More detail: [RFC-0001 section 3](../spec/rfc-0001-attenuo.md#3-delegation-chain-data-model) and [ADR-0005](../decisions/0005-policy-decision-point.md).
