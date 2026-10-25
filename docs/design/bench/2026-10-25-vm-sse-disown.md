# Stream-end shape check on the unfiltered SSE path: per-event cost (2026-10-25)

Branch `perf/sse-disown-cost`, main `2b495e2`. Summary and decision: [performance, Stream-end shape check on the unfiltered SSE path](../performance.md#stream-end-shape-check-on-the-unfiltered-sse-path-2026-10-25).

The question (board, the ticked look-alike stream-cut item): since #117 the SSE path without a list filter (a `tools/call` answer streamed as SSE, and the guarded passthrough) runs every framed event through `guard::disown_events`, which parses the event's data with `sse::event_json` to test `has_stream_end_shape` and re-serializes only a look-alike. Before #117 those events were framed and relayed unparsed. What does the check add per event? The lines set for a change: more than 0.2 ms per 85 KB event, or more than about 20 percent of the relay floor for small events.

## Environment

The shared 4-vCPU dev container of the other 2026-10 files (Intel Xeon @ 2.10 GHz), rustc 1.99.1, the workspace release profile (`lto = "thin"`, `codegen-units = 1`), built with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`. Load average 4.0 to 5.3 during the "before" and "scan per event" runs and 1.7 to 1.9 during the final runs; other work shared the host throughout.

## Method

`crates/attenuo-proxy/tests/listen_stream_cost.rs`, new `#[ignore]` test `disown`, in one thread: N events, each fed as its own chunk, through `SseFramer::push` alone (the relay floor: the unfiltered path before #117) and through `SseFramer::push` followed by the stream-end check, as `guard::disown_stream` runs it. The check is reached through `attenuo_proxy::testing` (`disown_events` on the first commit, `disown_chunk` after the change). Every pass asserts that no event was rewritten. Each printed number is the median of 15 timed passes; each cell was run 5 times, and the tables give the median of the 5 and their range.

Events (no event contains a `-`):

| name | bytes | N | what |
|---|---|---|---|
| `small` | 173 | 20,000 | `notifications/progress` with a token, progress, total and message (the `small` event of the listen-stream note) |
| `mid_result` | 8,164 | 2,000 | a `tools/call` answer with 19 tool-like objects under `result.structuredContent.items` |
| `large_result` | 85,099 | 200 | the same with 200 objects (the `large_result` event of the listen-stream note) |

```
export CARGO_TARGET_DIR=/home/claude/agent-target-ssecost CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo test --release -p attenuo-proxy --locked --test listen_stream_cost -- --ignored --nocapture --test-threads 1 disown
```

"Before" is the commit that added the test (`33f7547`, `disown_events` as merged in #117). "After" is the branch head.

## Before: every event parsed (us per event)

| event | relay | relay + check | added | added per KB | added / relay |
|---|---|---|---|---|---|
| `small` | 0.16 (0.16 to 0.24) | 1.12 (1.10 to 1.14) | **0.95** (0.90 to 0.98) | 5.64 (5.30 to 5.79) | 607 % (366 to 621) |
| `mid_result` | 6.54 (6.09 to 6.72) | 67.4 (65.7 to 69.6) | **61.3** (58.9 to 63.3) | 7.68 (7.39 to 7.94) | 952 % (877 to 1007) |
| `large_result` | 64.5 (60.1 to 65.7) | 716 (692 to 732) | **653** (631 to 668) | 7.86 (7.60 to 8.03) | 1028 % (965 to 1050) |

Raw lines:

```
disown small: event 173 B, relay 0.16 us, checked 1.12 us, added 0.96 us/event, 5.705 us/KB, 613% of relay
disown mid_result: event 8164 B, relay 6.37 us, checked 69.63 us, added 63.27 us/event, 7.936 us/KB, 994% of relay
disown large_result: event 85099 B, relay 63.03 us, checked 715.82 us, added 652.79 us/event, 7.855 us/KB, 1036% of relay
disown small: event 173 B, relay 0.24 us, checked 1.14 us, added 0.90 us/event, 5.304 us/KB, 366% of relay
disown mid_result: event 8164 B, relay 6.62 us, checked 67.43 us, added 60.81 us/event, 7.627 us/KB, 919% of relay
disown large_result: event 85099 B, relay 64.93 us, checked 732.48 us, added 667.55 us/event, 8.033 us/KB, 1028% of relay
disown small: event 173 B, relay 0.16 us, checked 1.11 us, added 0.95 us/event, 5.637 us/KB, 607% of relay
disown mid_result: event 8164 B, relay 6.72 us, checked 65.66 us, added 58.94 us/event, 7.393 us/KB, 877% of relay
disown large_result: event 85099 B, relay 64.46 us, checked 725.02 us, added 660.56 us/event, 7.949 us/KB, 1025% of relay
disown small: event 173 B, relay 0.16 us, checked 1.13 us, added 0.98 us/event, 5.786 us/KB, 621% of relay
disown mid_result: event 8164 B, relay 6.09 us, checked 67.35 us, added 61.27 us/event, 7.684 us/KB, 1007% of relay
disown large_result: event 85099 B, relay 65.69 us, checked 699.48 us, added 633.79 us/event, 7.626 us/KB, 965% of relay
disown small: event 173 B, relay 0.16 us, checked 1.10 us, added 0.95 us/event, 5.596 us/KB, 605% of relay
disown mid_result: event 8164 B, relay 6.54 us, checked 68.84 us, added 62.30 us/event, 7.814 us/KB, 952% of relay
disown large_result: event 85099 B, relay 60.14 us, checked 691.52 us, added 631.38 us/event, 7.597 us/KB, 1050% of relay
```

An earlier set of five runs (the `small` line lost to a filter in the shell, the rest identical in method) gave `mid_result` 59.4 to 63.3 us and `large_result` 621.5 to 649.7 us added.

Both lines are crossed: 0.65 ms per 85 KB event against 0.2 ms, and six times the stage's relay floor for a small event against 20 percent. The cost is linear in size, about 7.7 us per KB, which is `serde_json::from_str` into a `Value` (the same parse rate as the listen-stream filter's 0.6 to 0.7 ms per 85 KB).

## The change

`guard::may_hold_stream_end_code` scans the raw bytes for a JSON number that could have the value `-32001`, and only an event that passes is parsed. A JSON number cannot be escaped, starts with a literal `-`, and is one unbroken run of `0-9 . e E + -`; whatever its spelling (`-32001`, `-32001.0`, `-3.2001e4`, `-3.2001E+4`, `-0.32001e5`, `-320010e-1`, or a long decimal that rounds to it, such as `-32000.99999999999999999`), its significant digits (the digits and points after the `-`, points dropped, leading zeros dropped) start with `32001`, or with `320009` for a value just under 32001 in magnitude. A plain search for `-32001` would miss `-3.2001e4` and the rounded spellings, so the scan checks the significant digits instead; the exponent is not read, and a wrong magnitude is a false positive the parse rejects. The reasoning is in the function's doc comment, and unit tests run every spelling serde_json writes (`-32001`, `-32001.0`) and a table of hand-written ones (exponent forms, every position of the point, leading and trailing zeros, the rounded forms, surrounding whitespace) through `has_stream_end_shape`, the scan and `disown_events`.

A first version scanned each event after splitting the chunk and still copied every event into a new buffer:

| event | added, scan per event (5 runs) |
|---|---|
| `small` | 0.24 (0.24 to 0.44) |
| `mid_result` | 7.18 (6.78 to 7.29) |
| `large_result` | 67.8 (29.9 to 71.9) |

So the split and the copy were most of what was left. The kept version, `guard::disown_chunk`, scans the whole chunk first and returns it unchanged, without a copy, when nothing in it passes; the scan over a chunk sees every event's bytes, and a number never runs across the empty line that ends an event. Only a chunk that passes goes through `disown_events`, which scans and parses event by event as before.

## After: byte scan, chunk passed through (us per event)

| event | relay | relay + check | added | added per KB | added / relay |
|---|---|---|---|---|---|
| `small` | 0.16 (0.15 to 0.16) | 0.22 (0.21 to 0.24) | **0.06** (0.06 to 0.08) | 0.36 (0.34 to 0.49) | 39 % (37 to 54) |
| `mid_result` | 6.80 (6.48 to 8.28) | 8.69 (8.44 to 8.76) | **1.85** (0.49 to 2.21) | 0.23 (0.06 to 0.28) | 27 % (6 to 34) |
| `large_result` | 62.2 (59.7 to 64.9) | 88.6 (86.3 to 89.5) | **26.6** (23.7 to 27.1) | 0.32 (0.29 to 0.33) | 43 % (37 to 44) |

Raw lines:

```
disown small: event 173 B, relay 0.16 us, checked 0.21 us, added 0.06 us/event, 0.340 us/KB, 37% of relay
disown mid_result: event 8164 B, relay 6.80 us, checked 8.44 us, added 1.64 us/event, 0.206 us/KB, 24% of relay
disown large_result: event 85099 B, relay 59.71 us, checked 86.26 us, added 26.55 us/event, 0.320 us/KB, 44% of relay
disown small: event 173 B, relay 0.16 us, checked 0.23 us, added 0.07 us/event, 0.425 us/KB, 45% of relay
disown mid_result: event 8164 B, relay 6.48 us, checked 8.70 us, added 2.21 us/event, 0.278 us/KB, 34% of relay
disown large_result: event 85099 B, relay 61.70 us, checked 87.07 us, added 25.37 us/event, 0.305 us/KB, 41% of relay
disown small: event 173 B, relay 0.16 us, checked 0.22 us, added 0.06 us/event, 0.349 us/KB, 37% of relay
disown mid_result: event 8164 B, relay 8.28 us, checked 8.76 us, added 0.49 us/event, 0.061 us/KB, 6% of relay
disown large_result: event 85099 B, relay 62.19 us, checked 88.74 us, added 26.55 us/event, 0.319 us/KB, 43% of relay
disown small: event 173 B, relay 0.15 us, checked 0.24 us, added 0.08 us/event, 0.494 us/KB, 54% of relay
disown mid_result: event 8164 B, relay 6.84 us, checked 8.69 us, added 1.85 us/event, 0.232 us/KB, 27% of relay
disown large_result: event 85099 B, relay 64.88 us, checked 88.62 us, added 23.74 us/event, 0.286 us/KB, 37% of relay
disown small: event 173 B, relay 0.16 us, checked 0.22 us, added 0.06 us/event, 0.363 us/KB, 39% of relay
disown mid_result: event 8164 B, relay 6.53 us, checked 8.65 us, added 2.12 us/event, 0.265 us/KB, 27% of relay
disown large_result: event 85099 B, relay 62.34 us, checked 89.47 us, added 26.55 us/event, 0.326 us/KB, 43% of relay
```

## Readings

- **85 KB: 653 us added before, 27 us after**, about 25 times less and well under the 0.2 ms line. What is left is the byte scan, about 0.3 us per KB, against a framer that costs about 0.75 us per KB.
- **Small events: 0.95 us added before, 0.06 us after.** That is still 39 percent of the stage's relay floor of 0.16 us, above the 20 percent line taken literally, but 60 ns in absolute terms; end to end, the relay floor of one HTTP chunk per event measured in the [listen-stream note](2026-10-24-vm-listen-stream-filter.md) is about 40 us, so the scan is about 0.15 percent of it. A faster search (a `memchr` for `-`) could cut it further; not worth a dependency here.
- **A look-alike, or an event whose bytes pass the scan, costs what it did before** plus the scan: it is parsed, and rewritten if it has the shape. Events that fail the scan go out byte for byte, as they did before when they were parsed and found not to be look-alikes, so the output is unchanged.
- Not measured: end to end through the proxy (the stage difference is far below the 40 us floor there), and events dense with `-` digits (for example negative numbers starting `32001`), where the scan sends more events to the parser; each such false positive costs one parse, as every event did before.

## Reproduce

```
cargo test --release -p attenuo-proxy --test listen_stream_cost -- --ignored --nocapture --test-threads 1 disown
```

For "before", check out `33f7547` and run the same command.
