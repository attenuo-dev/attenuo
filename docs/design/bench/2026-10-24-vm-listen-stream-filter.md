# Listen-stream list filter: per-event cost (2026-10-24)

Branch `feat/proxy-followups-2`, main `5d86c19`. Summary and decision: [performance, Listen-stream list filter](../performance.md#listen-stream-list-filter-2026-10-24).

The question (board follow-up from #90): since #90 the proxy runs every event of a `GET` listen stream through `sse::rewrite_stream` with the list filter (`listen_list_filter` in `proxy.rs`), so every event that carries JSON is parsed, checked for a list shape (`filter::list_kinds_by_shape`) and serialized again. Before, the stream went through `sse::frame_stream`, which only finds event boundaries and relays the bytes. What does that add per event, for the small events a listen stream mostly carries and for a large list answer? The threshold set for a change was 20 us per small event.

## Environment

The shared 4-vCPU dev container of the other 2026-10 files, rustc 1.99.1, the workspace release profile (`lto = "thin"`, `codegen-units = 1`). Load average 2.0 to 3.2 during the runs.

## Method

`crates/attenuo-proxy/tests/listen_stream_cost.rs`, two `#[ignore]` tests:

1. **`stage`**: the SSE stage alone, in one thread. 20,000 small events (or 200 large ones), each fed as its own chunk, through `SseFramer::push` (the relay before #90) and through `SseRewriter::push` with the proxy's filter closure rebuilt from the public API (the same `list_kinds_by_shape` and `ListFilter::apply_message`; the SR-25 bookkeeping of listed tool names, which runs only on list answers, is left out). Median of 15 timed passes per cell.
2. **`end_to_end`**: a `GET /mcp/github` through the real proxy router (`StaticAuthorizer`, stream guard and listen-stream labeller on, as in the server) to an upstream that writes N events and closes the stream; the client reads until the end and counts events. Median of 9 runs after one warm-up run. "Before" is the same binary built with the filter argument replaced by `None` (local edit, not committed), so the stream goes through `frame_stream` as before #90.

Events:

| name | bytes | what |
|---|---|---|
| `small` | 173 | `notifications/progress` with a token, progress, total and message |
| `large` | 85,064 | `tools/list` answer with 200 tools (name, description, a 3-property input schema, annotations); the chain's capability `github:tool_0*` keeps 100 |
| `large_result` | 85,099 | the same 200 objects under `result.structuredContent.items`: not a list, nothing removed |

The chain is `user:a` / `agent:a` with the one capability above. No calls are awaited, so the labeller passes every event without parsing it in both builds.

## Stage alone (us per event, after #90)

Five runs, each the median of 15 passes:

| event | relay (`SseFramer`) | filter (`SseRewriter` + closure) | added |
|---|---|---|---|
| `small` | 0.15 to 0.16 | 1.70 to 1.74 | 1.54 to 1.59 |
| `large` | 70.0 to 102.0 | 705 to 753 | 603 to 681 |
| `large_result` | 71.5 to 73.5 | 738 to 817 | 665 to 745 |

Two earlier runs without `large_result` gave the same: `small` added 1.51 and 1.51 us, `large` added 630 and 628 us.

## End to end (us per event, median of 9 runs, events per second in brackets)

| event | before (relay) | after (filter) |
|---|---|---|
| `small` | 39.1, 39.7, 38.3, 40.9, 42.4, 40.9, 39.4, 39.5 (23,600 to 26,100/s) | 39.5, 10.8, 15.7, 10.5, 11.7, 22.6, 39.9, 39.8 (25,100 to 95,200/s) |
| `large` | 142, 139, 133, 165, 164, 135, 277, 164 (3,600 to 7,500/s) | 1,255, 1,444, 1,427, 1,473, 1,494, 1,325, 1,373, 1,360 (670 to 800/s) |
| `large_result` | 144, 166, 135, 150, 174, 157, 138, 162 (5,800 to 7,400/s) | 1,083, 1,031, 1,137, 990, 1,072, 991, 1,031, 1,071 (880 to 1,010/s) |

The client read one chunk per small event in both builds (20,007 or 20,008 reads for 20,000 events), and 330 to 426 reads for the 300 large ones.

## Readings

- **Small events: 1.5 us added, not material.** The stage measures 1.54 to 1.59 us per notification-sized event, a thirteenth of the 20 us threshold. End to end the difference does not show: the relay floor here is one HTTP chunk per event through two hyper hops, about 40 us per event, and the after build was bimodal (four runs near 40 us, the rest at 10 to 23 us) while the before build stayed near 40 us in all eight. The client read the same number of chunks in both, so the faster runs are not coalescing at the client; the cause (scheduling of the proxy's tasks on the shared host) was not established. Either way, the filter does not make the small-event stream measurably slower end to end.
- **Large events: about 0.6 to 0.7 ms added in the stage, 1.1 to 1.3 ms end to end for the list answer and 0.8 to 1.0 ms for the non-list one** (85 KB, against 0.07 ms to frame it and 0.13 to 0.28 ms to relay it end to end). For a list answer this is the filter doing its job, the same parse, filter and serialize a `POST` answer gets; a list answer on the listen stream appears only when an upstream replays a broken `POST` stream or answers there after a `202`. For a large event that is not a list (`large_result`), it is the parse and re-serialization alone, about the same cost.
- **The cheap path was not built.** It would skip `serde_json::from_str` for events whose bytes contain none of the four list keys. Its saving on small events is at most the 1.5 us measured. It also has to stay correct: a JSON key can be spelled with `\u` escapes (`"tools"`), so the byte search would have to send any event containing a backslash-`u` through the parser too, and every event it skips would keep its original bytes, duplicate members included, where today every JSON event on the stream is re-serialized from one parse. Not worth it at 1.5 us. If large non-list events on listen streams turn out to be common, that is where it would pay (about 0.7 ms per 85 KB event), and it is on the board.

## Reproduce

```
cargo test --release -p attenuo-proxy --test listen_stream_cost -- --ignored --nocapture --test-threads 1
```

For "before", replace `Some(filter)` with `None::<fn(&mut Value)>` in the `stream_response_sse` call of `handle_passthrough` (`crates/attenuo-proxy/src/proxy.rs`) and run `end_to_end` again.
