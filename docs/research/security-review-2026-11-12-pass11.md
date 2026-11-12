# Security review, pass 11

- Date: 2026-11-12
- Branch: `fix/security-pass-11` (base: `c2bce7f` on main for the review; the fixes on `43efc7f`)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [pass 7](security-review-2026-10-25-pass7.md), [pass 8](security-review-2026-11-05-pass8.md), [pass 9](security-review-2026-11-06-pass9.md), [pass 10](security-review-2026-11-06-pass10.md), [threat model](../spec/threat-model.md), [task board](../tasks/board.md)

## Scope and method

What merged on 2026-11-12, #229 to #244 (`11aba06..c2bce7f`). In order of how much was read:

- #238: the `path_prefix` constraint (`capability.rs` `parse_path`, `path_within`, attenuation through `implies`) and the SR-100 fix (`limits.rs` `written_host`);
- #234 and #240: the single-writer fence (`sqlite/fence.rs`), the bounded audit append queue (`sqlite/log.rs` `Writer::append`, `writer_loop`), the read-only reader connection and `SharedPolicy`;
- #241: the loopback checks (`config.rs` `url_host_is_loopback`, `DevSection::check`) and the key-fetch transport (`idp/jwks.rs`);
- #243: subject redaction and JSON logs;
- #244: the SDK approval calls.

The AgentDojo planner tooling (#233, #235) was only checked for secrets and for endpoints off loopback. #229, #230, #232, #239 and #242 are documentation; #236 is a dependency bump, read for API changes only.

The review itself was done by reading the code, without building or running it, so each finding was first labelled "confirmed by reading" (the exact lines that make the input succeed are cited) or "suspected" (it needs a test, or depends on a client or platform outside this repository). Each finding then got a test written before its fix, which shows whether it reproduces; every test below failed before its fix, except SR-106's, which pins documented behaviour. The attacker is as in pass 10, plus a local user on the server's host without the server's account (SR-103) and whoever answers the resolver for the name `localhost` (SR-107). Findings are numbered from SR-102.

## Summary

| Severity | Found | Fixed (here or later) | Proposed (maintainer decides) | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 0 | 0 | 0 | 0 |
| Low | 2 | 2 | 0 | 0 |
| Info | 4 | 4 | 0 | 0 |
| **Total** | **6** | **6** | **0** | **0** |

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| SR-102 | Low | audit (`sqlite/log.rs` `Writer::append`), server (`authz/pipeline.rs` audit-error branch) | An append that timed out after the writer took it could still be committed, after the pipeline had refunded the charge and given the approval back | Fixed, test `a_taken_append_is_waited_for_past_the_timeout_sr102` |
| SR-103 | Low | audit (`sqlite/fence.rs`, `sqlite/connection.rs`), server (`state.rs`) | The lock file was created `0644`, so any local user could open it and hold the fence while the server was down; the database files were world-readable too | Fixed, tests `the_lock_file_is_owner_only_sr103`, `new_database_files_are_owner_only_sr103`, `an_existing_database_keeps_its_mode_sr103`, `storage_files_are_owner_only_sr103`, `the_fenced_error_does_not_name_the_recorded_pid_as_the_holder` |
| SR-104 | Info | core (`limits.rs` `Derive::Host`) | A percent-encoded IDNA deviation character in the host passed the SR-100 refusal | Fixed, test `idna_deviation_characters_in_the_host_have_no_host_sr100` (extended) |
| SR-105 | Info | core (`capability.rs` `parse_path`), Python and TypeScript SDKs | `path_prefix` admitted full-width dots and slashes and double percent-encoding, which some tools turn into `..` | Fixed, test `path_prefix_refuses_what_its_model_cannot_reason_about_sr105` |
| SR-106 | Info | core (`ArgConstraint::PathPrefix` docs), `docs/concepts/capabilities-and-attenuation.md` | `path_prefix` compares text and does not see symbolic links; no doc said so | Done (docs), test `path_prefix_compares_text_and_does_not_see_links_sr106` pins the lexical comparison |
| SR-107 | Info | server (`idp/jwks.rs` `fetch_client`, `config.rs` `url_host_is_loopback`) | Plain-http key fetches trusted the name `localhost` as the resolver answered it | Fixed, test `localhost_is_pinned_to_loopback_whatever_the_resolver_says_sr107` |

## Findings

### SR-102: a timed-out append could still commit an `allow` whose charge and approval were rolled back (Low, fixed)

- **Component.** `attenuo-audit` `sqlite/log.rs` `Writer::append` (the timeout arm) and `writer_loop`; `attenuo-server` `authz/pipeline.rs`, whose audit-error branch calls `give_back` and `refund_unrecorded` for every `AuditError`.
- **Observation.** The writer marked a queued job taken as it dequeued it, before it had the connection. A caller whose wait ran out after that point got `Overloaded` ("did not commit the record within the append timeout") while the writer could still commit the record. The pipeline then denied the call with `audit_error`, refunded its budget charge and gave its approval back, and the `allow` record, with the charge and the consumed approval, appeared in the log afterwards. `AuditSink::append` says that on an error "nothing is appended", and `refund_unrecorded` relies on that: "a budget is spent exactly when an allowed decision that charged it is in the log".
- **Sequence.** A run has a `sum` limit of 5000 on `amount`. Call C (`amount = 3000`) is allowed and charged, and its record is queued. The writer takes it and stalls on a slow disk past `append_timeout_seconds`. The caller is told `audit_error`, the 3000 is refunded, and then the commit succeeds. The agent sends C again; it is allowed and charged. The log now shows 6000 charged against a limit of 5000, and one approval consumed by two `allow` records, while one call ran. Nothing ran that should not have, so this is the integrity of the evidence, not enforcement: an auditor or a SIEM rule that rebuilds budgets from the signed log sees a breach that did not happen.
- **Reproduced.** A test-only gate holds the writer between taking a batch and committing it, so the caller's deadline runs out at exactly that point (no sleeps decide the order). Before the fix the caller returned `Overloaded("the audit writer did not commit the record within the append timeout")` while the record was still to be committed.
- **Fix.** The writer claims its jobs only once it holds the connection, right before the commit, and a caller whose job was claimed waits for the commit's answer without a deadline. A job not taken within the timeout is withdrawn and never written, as before. So `Overloaded` again means "not written and never will be", which is what the refund and the give-back assume. The wait is bounded in threads: the writer commits one batch at a time, so at most `MAX_BATCH` (256) callers wait on a stuck commit, which an inline commit already did for one caller; everything queued behind it is still withdrawn at the deadline. A writer that waits for a connection held by something else (a long verify, say) no longer claims the jobs it holds, so their callers are withdrawn at the deadline instead of waiting.
- **Rejected.**
  - A cancel flag the writer checks before committing: the commit itself (its `fsync`) is where a hung disk stalls, so a flag checked before it leaves the same window.
  - Keeping the charge and the approval spent when a taken job times out, and denying (fail closed): the commit can still fail afterwards, and then a budget is spent with no record, the invariant broken in the other direction.
  - A compensating `decision_void` record written for an abandoned job: a new record kind that every log reader must understand, written to the same stuck disk, so it can be lost the same way.
- **Test.** `sqlite::tests::a_taken_append_is_waited_for_past_the_timeout_sr102` (attenuo-audit): the caller has not returned ten timeouts after the writer took its record; once the writer is released the caller gets the committed entry, the log holds it, and no timeout is counted. Run 300 times in a loop without a failure, with `a_stuck_writer_times_appends_out_and_never_writes_withdrawn_ones`, `a_full_writer_queue_sheds_appends_at_once` and `bounded_queue_keeps_group_commit_and_order` 50 times each.

### SR-103: any local user who could read the lock file could hold the fence (Low, fixed)

- **Component.** `attenuo-audit` `sqlite/fence.rs` `WriterFence::acquire`; `sqlite/connection.rs` `open_connection`; `attenuo-server` `state.rs` `open_storage`.
- **Observation.** The lock file was opened with `create(true)` and no mode, so it was created `0666` less the umask, usually `0644`. `flock(2)` locks a file whatever mode it was opened in, so a read-only descriptor is enough. Another local user could lock it during any gap between server instances (a restart, a crash, a rolling update), and every later start failed with the fence error until an operator found and stopped that process. The error made that harder: it said "another process holds ... (pid N)" with the pid written in the file, which is the last attenuo server's, not the holder's. SQLite also created `audit.sqlite`, `-wal` and `-shm` `0644`, so local users could read the audit log, subjects included.
- **Reproduced.** Before the fix the lock file and a new database file were `0644` under the usual umask.
- **Fix.** On Unix:
  - the lock file is created `0600`, and an existing one with a wider mode is narrowed to `0600` (when the server may change it, that is when it owns the file or runs as root; otherwise it is left as it is);
  - a new database file is created `0600` before SQLite opens it, and SQLite gives the `-wal` and `-shm` files it creates the database file's mode;
  - a data directory the server creates for `sqlite_path` is `0700`;
  - an existing database file or directory keeps its mode, so a file an operator made group-readable on purpose (for a backup user, say) stays that way, and so do its `-wal` and `-shm` files.

  The fence error now reads "`<lock>` is locked by another process: ... The lock file records pid N, the last attenuo server that took it; if that process is gone, another program holds the lock (find it with `fuser` or `lsof`)." The reference and the deployment guide say the same.
- **Not done.** Refusing to start when the lock file belongs to another user, which the review suggested as an option. The directory's permissions decide who can create a file there, and a server run under a different account from before would then refuse to start for a reason unrelated to a second server.
- **Tests.** `sqlite::fence::tests::the_lock_file_is_owner_only_sr103` (new file `0600`; an existing `0644` file narrowed), `sqlite::tests::new_database_files_are_owner_only_sr103` (database, `-wal`, `-shm` all `0600`), `sqlite::tests::an_existing_database_keeps_its_mode_sr103` (a `0640` database keeps `0640`, and its `-wal` and `-shm` get `0640`), `state::tests::storage_files_are_owner_only_sr103` (the server's data directory `0700` and its four files `0600`), `sqlite::fence::tests::the_fenced_error_does_not_name_the_recorded_pid_as_the_holder`. The first two failed before the fix.

### SR-104: a percent-encoded IDNA deviation character skipped the SR-100 refusal (Info, fixed)

- **Component.** `attenuo-core` `limits.rs` `Derive::Host::apply` and `written_host`.
- **Observation.** The SR-100 check looks for `ß`, `ς`, ZWJ, ZWNJ and `ẞ` in the host as written. WHATWG percent-decodes a host before it maps it, so `https://fa%C3%9F.example/` has no `ß` as written, and the `url` crate counted it as `xn--fa-hia.example`, possibly a host already seen. A client that decodes the escape and then maps the name the IDNA 2003 way would reach `fass.example`. Go's `net/url` decodes a percent-encoded host, and Go before 1.18 mapped names transitionally, so only older clients are affected. Python's stdlib looks the escaped text up as it is, and Node and curl agree with the crate.
- **Reproduced.** Before the fix `https://fa%C3%9F.example/` and `fa%C3%9F.example` had the host `xn--fa-hia.example`.
- **Fix.** A value whose host, as written, holds a `%` has no host, so a host limit answers `limit_arg_invalid` and run usage counts the value as itself. A host name has no reason to be percent-encoded, and the clients do not agree on how to read one, so this is simpler than decoding first and checking again, and it also covers spellings other than the deviation characters. `https://a.ex%61mple/`, which counted as `a.example`, now has no host; a `%` in the path, query, fragment or user info does not matter.
- **Rejected.** Decoding the host once and checking the result: it follows WHATWG exactly, but leaves the crate's reading of an escaped host to stand for clients that read it differently.
- **Test.** `limits::tests::idna_deviation_characters_in_the_host_have_no_host_sr100` gains `https://fa%C3%9F.example/`, `fa%C3%9F.example`, `https://%CF%83%CF%82.example/`, `https://FA%E1%BA%9E.example/` and `https://a%E2%80%8Db.example/` (no host), and `https://a.example/%C3%9F?q=%CF%82#%25` and `https://%C3%9F@a.example/` (host `a.example`). `non_special_schemes_have_no_host_fz2_2` now expects no host for `https://a.ex%61mple/`.

### SR-105: `path_prefix` admitted spellings that some tools turn into `..` (Info, fixed)

- **Component.** `attenuo-core` `capability.rs` `parse_path`; the mirrors in the SDKs, `path_problem` (Python) and `pathProblem` (TypeScript).
- **Observation.** `parse_path` models ASCII separators and one percent-decode. Under `path_prefix: "/workspace"` it admitted `/workspace/．．/secrets/key` (U+FF0E twice), `/workspace/‥/x` (U+2025), `/workspace/a／..／..／etc` (U+FF0F) and `/workspace/%252e%252e/etc/passwd`. NFKC normalisation turns the first three into `..` and `/`, so does Windows "best fit" conversion in a tool that calls an ANSI file API, and a tool that percent-decodes twice turns the last into `../`. Each needs a particular tool or platform, hence Info.
- **Fix.** The parser refuses what it cannot reason about, rather than normalise Unicode:
  - every code point whose NFKC form is made only of `.`, `/` and `\` (checked against Unicode 15.1): U+2024, U+2025, U+2026, U+FE19, U+FE30, U+FE52, U+FE68, U+FF0E, U+FF0F, U+FF3C;
  - three slashes that Windows best-fit conversion maps to `/`: U+2044, U+2215, U+29F8;
  - `%25` followed by two hex digits, an escape that one decode turns into another escape.

  The list is `attenuo_core::LOOKALIKE_SEPARATORS`, documented next to the constraint. Code points whose NFKC form mixes a dot or slash with letters or digits (`⒈` is `1.`, `℀` is `a/c`) cannot form a `.` or `..` segment on their own and are admitted. Code-page specific best-fit mappings beyond these, such as the yen sign read as `\` on a Japanese code page, are not modelled; the docs say so. The SDKs' path checks refuse the same, so a constraint they build is not refused by the server.
- **Admitted still.** Ordinary non-ASCII names (`café.txt`, `日本語/文書.md`, `naïve résumé.docx`), a literal `%` (`50%.txt`), and `%25` not followed by two hex digits (`100%25.txt`).
- **Test.** `capability::tests::path_prefix_refuses_what_its_model_cannot_reason_about_sr105` (the four inputs above and the rest of the list are refused with the new reasons; the names above are admitted); Python `test_path_prefix_refuses_what_the_server_refuses` and `test_path_prefix_accepts_plain_paths`, TypeScript `refuses a path_prefix path the server refuses, saying why`, each extended.

### SR-106: `path_prefix` is lexical, so a symbolic link below the prefix leads outside it (Info, done in the docs)

- **Component.** `ArgConstraint::PathPrefix` docs; `docs/concepts/capabilities-and-attenuation.md`.
- **Observation.** With `fs:read_file{path: path_prefix "/workspace/"}` and a tool that clones a repository into `/workspace`, a repository holding `docs -> /home/user/.ssh` makes `read_file("/workspace/docs/id_ed25519")` pass every rule, and the upstream follows the link. The same holds if any granted tool can create a link under the prefix. The engine cannot check the upstream's file system, so this is by design, but nothing said so, and "a path at or below this one" reads as a containment guarantee.
- **Done.** Both places now say that `path_prefix` compares the text of the path and does not resolve symbolic links, and tell the operator what to do: pair it with an upstream that resolves the real path and checks it against its own allowed directories (the reference MCP filesystem server does), or do not grant tools that can create links or check out untrusted content under the prefix.
- **Test.** `capability::tests::path_prefix_compares_text_and_does_not_see_links_sr106` pins that `/workspace/link/id_ed25519` is admitted under `/workspace/`. It passed before as well: the change is the documentation.

### SR-107: plain-http key fetches trusted the name `localhost` as the resolver answered it (Info, fixed)

- **Component.** `attenuo-server` `idp/jwks.rs` `fetch_client` and `check_fetch_url`; `config.rs` `url_host_is_loopback`.
- **Observation.** `check_fetch_url` accepts plain `http://` for a loopback host, and `localhost` passed on its name. The system resolver decides what `localhost` is: on a host or container whose `/etc/hosts` has no `localhost` line, or where `nsswitch` asks DNS first, the name can be looked up in DNS, through the search list as `localhost.<search domain>`, and answered with any address. The server would then fetch an IdP's key set, a SPIFFE bundle or a discovery document over cleartext from another machine, and trust the keys in it. RFC 6761 says resolvers should answer `localhost` themselves but does not make them.
- **Reproduced.** The test builds the key-fetch client over a resolver that answers `localhost` with 192.0.2.1 (an address reserved for documentation); without the fix the client asked that resolver and tried to connect there.
- **Fix.** The key-fetch client connects the name `localhost` to `127.0.0.1` or `[::1]` itself and never asks the resolver for it (`reqwest`'s per-name override; the URL's port is kept). Configurations and demos that use `http://localhost:...` keep working, and the exception stays on the machine whatever the resolver says. Every key fetch (an IdP's `jwks_url`, its discovery document and the `jwks_uri` it names, SPIFFE bundles) goes through this client.
- **Rejected.** Accepting only literal loopback addresses for plain http: it breaks every local setup and demo that writes `localhost`, and gives the operator an error for a name that is almost always safe. Resolving and then requiring every address to be loopback: it still depends on the resolver, adds a lookup and a time-of-check gap before the connect, and needs a custom resolver anyway. `[server] public_url` keeps accepting the name, since nothing is fetched from it.
- **Test.** `idp::jwks::tests::localhost_is_pinned_to_loopback_whatever_the_resolver_says_sr107`: a key server on 127.0.0.1, a client with the pin over a resolver that answers 192.0.2.1; the fetch from `http://localhost:<port>/jwks` succeeds and the resolver is never asked.

## Checked and found sound

**`path_prefix` (#238)**

- `..` and `.` segments are refused, including a leading `./`, a trailing `/..` and `..` as the whole value. `.foo`, `..foo` and `...` are ordinary names and are admitted.
- `//` anywhere is refused, as are a backslash, every control character (C0, DEL, C1) and `%2e`, `%2f` and `%5c` in either case. A NUL, raw or `%00`, cannot escape: truncating at it only shortens a path that already passed the segment test.
- `/a/b` against `/a/bc` is compared by segment, so it is refused. An empty prefix is refused. `/` is a valid prefix with no segments.
- Absolute and relative values never match each other. `file:///...` is relative with `//`, so it is refused. A Windows `C:/x` is relative, so an absolute prefix refuses it.
- Trailing slash: `/a/b/` under `/a/b` is admitted. Under `/a/b/`, `/a/b` is refused and `/a/b/` and `/a/b/c` are admitted.
- The comparison is case-sensitive, which can only under-admit on a case-insensitive file system, never widen.
- Attenuation: a narrower `path_prefix` is tested as "is its path a value the wider one admits", which holds for every value it admits, so `/a/` cannot become `/a` and `/a` cannot become `/` or `/a-old`. A `path_prefix` under a `prefix` holds exactly when its path starts with the prefix. `prefix` under `path_prefix` is never allowed; `equals` and `one_of` go through the value check. An invalid `path_prefix` that was never checked admits nothing.
- Deserialisation checks the path, so an invalid prefix in a token, an exchange or the config is refused when it is read.
- Non-string values never satisfy the constraint. The violation message echoes the constraint's own path, never the value. The proxy's list filter uses the same check, and run limits treat `path_prefix` as non-numeric.

**The written host (#238)**

- For special schemes the host is read after `scheme:` and any leading `/`, up to `/`, `?` or `#`, after the last `@`, which matches WHATWG's authority splitting once SR-56 has refused backslashes, whitespace and control characters. `http:faß.example`, `HTTPS://`, user info, ports and both cases of `ẞ` are covered by tests. No other character maps under UTS 46 to `ß`, `ς`, ZWJ or ZWNJ.

**The writer fence, bounded appends, the reader connection and `SharedPolicy` (#234, #240)**

- The fence is taken before the database is opened. A stale lock file does not block, because the lock and not the file is the fence, and the file is never removed, so there is no race on unlinking it. Two spellings of one path resolve to one lock. Hard links to the database would get separate lock files, an edge case that needs operator misconfiguration. No other binary in the workspace opens the file for writing. The pid in the file is informational only (see SR-103 for the error text).
- A withdrawn job is never written: the claim's compare-and-swap makes "taken" and "abandoned" mutually exclusive, so the chain stays linear. Only the taken-then-timed-out path was a problem (SR-102).
- The reader connection is read-only and opened only in WAL mode, and every read is a whole committed transaction, so a torn batch is never visible. Verification fixes the upper sequence number and the checkpoints in one read transaction, then pages through entries up to it; nothing deletes from the log or the checkpoints, so the pages are stable. Appends compute `prev_hash` on the writer's own transaction, never from the reader, so a stale reader cannot fork the chain. A head read from the reader may be older but is still a valid head.
- A decision takes one policy snapshot for every stage. Reloads are serialised, there is one swap site and no lost update. Lock poisoning is handled safely, since the lock guards one reference. The output-label and tool-lookup paths take their own snapshots, but neither is a decision, and only an admin reload can change them.
- `/readyz` returns only fixed strings. Error text goes to the log (SR-38 holds), and the audit readiness check reads a flag, not the database.

**Network hardening (#241)**

- `url_host_is_loopback` parses with WHATWG first, so `localhost@evil`, user info, `localhost.example.com`, `127.0.0.1.nip.io` and `/127.0.0.1` in the path all fail. `127.1`, `2130706433`, `0x7f.1` and `127.0.0.1.` normalise to real loopback addresses. `[::ffff:127.0.0.1]`, `0.0.0.0`, `[::]` and `localhost.` are refused (fail closed).
- The `[dev]` loopback check uses the address `serve` binds, which neither the command line nor the environment overrides. The console listener never mounts the root-token route.
- Key fetches follow no redirects, and each 3xx is refused naming its `Location`. The URL check runs on the configured URL, the issuer used for discovery and the discovered `jwks_uri`, so an https IdP cannot point to an http `jwks_uri` off loopback.

**Subject redaction and JSON logs (#243)**

- Every log line that names a user goes through the redaction helper: the decision line, token issuance, IdP intake, the dev root token, the approver, the proxy request span, the lease-refusal line and the stream-guard lines.
- No log line prints a whole chain, claims or request with `Debug`. The request span records the route template, never the URI (SR-90 holds). Webhook and S3 failures log only the status, never a response body.
- The redaction key is derived from the issuer key with a label, so digests match across replicas that share the issuer key and differ between deployments. 64 bits is enough for log correlation.
- JSON values are escaped by serde, field names are static and collide with none of the envelope's fields, and the text format keeps the `Debug` escaping (SR-18).

**SDK approval calls (#244)**

- Granting and declining an approval send the ID token as a plain bearer header on the client's own base URL, never over the DPoP path and never retried with a nonce. It is not logged, and transport errors carry only the method and URL.
- Python's `httpx` does not follow redirects by default; modern `fetch` implementations drop `Authorization` on a cross-origin redirect.
- Path segments are percent-encoded and `.` and `..` refused, so URL dot-segment handling cannot be triggered.
- The session id goes only into a header, and both HTTP clients refuse CR and LF in header values. The timeout error type changes classification only, and the TypeScript timeout is replaced, not dropped, when the caller passes its own signal.

**AgentDojo planner grants (#233, #235)**

- No network clients, no API keys or other secrets. The replay server and the fake upstream bind loopback, and the admin token is a fixed test value on a loopback-only server. The frozen grant and result files hold only task data.

## Not covered

- The review was done by reading; the tests above were added afterwards. Fuzzing was not run.
- SR-102 was measured in the audit crate with a gate on the writer, not through the proxy against a stalled disk.
- SR-104: Go's `net/url` and older Go IDNA mappings were not run; the refusal does not depend on them.
- SR-105: Windows best-fit tables were not checked beyond the code points listed; NFKC was checked with Python's `unicodedata` (Unicode 15.1).
- SR-107: the pin was tested with a substitute resolver in the client, not on a host whose system resolver sends `localhost` to DNS.
