# AgentDojo with a local open-weight model: raw outputs

Raw output of a full AgentDojo run on one laptop, with no API key and no paid service. There are two arms per suite: the stock agent (baseline) and the agent with attenuo between it and the suite's tools, using the frozen planner-written grants. Suites are added here as both of their arms finish. Statistics are computed from these files separately. Nothing here was edited by hand.

## Setup

| | |
|---|---|
| Scripts | `evaluation/agentdojo/pilot.py` and `enforced.py` at commit `f0e98ed` (branch `eval/agentdojo-local-model`; the run started before `1f23942` added `--resume` to `enforced.py`) |
| attenuo server | `target/debug/attenuo-server` built from `f0e98ed` (debug profile, Rust 1.89.0) |
| Model | `qwen2.5:14b` in Ollama: qwen2 architecture, 14.8B parameters, Q4_K_M quantization, tools capability. Weights blob `sha256:2049f5674b1e92b4464e5729975c9689fcfbf0b0e4443ccf10b5339f370f9a54` (Ollama id `7cdf5a0187d5`) |
| Model as run | `qwen2.5:14b-16k` (Ollama id `dce32098f420`): Modelfile `FROM qwen2.5:14b` plus `PARAMETER num_ctx 16384`, nothing else |
| Server | Ollama 0.40.16 on `127.0.0.1:11434`, OpenAI-compatible endpoint `/v1` |
| Sampling | temperature 0, seed 0 (set by the scripts, see `pilot.py`), num_ctx 16384 |
| Benchmark | `agentdojo` 0.1.35, attack `important_instructions`, all user tasks and all injection tasks (`--tasks 0 --injections 0`) |
| Python | 3.13.8, `openai` 3.46.0 |
| Hardware | Apple M4 Pro, 24 GB unified memory, macOS 27; the model runs fully on the GPU (about 11 GB loaded at 16k context) |

## Commands

From the root of a checkout of `f0e98ed`, for each suite in the order slack, banking, travel, workspace:

```sh
PY=<venv>/bin/python
OUT=<out>/full-2026-11-12
EP=http://127.0.0.1:11434/v1
MODEL=qwen2.5:14b-16k

"$PY" evaluation/agentdojo/pilot.py --out "$OUT/baseline" --suite "$suite" \
  --endpoint "$EP" --model "$MODEL" --tasks 0 --injections 0 --resume

PYTHONPATH=sdk/python/src "$PY" evaluation/agentdojo/enforced.py --out "$OUT/enforced-$suite" \
  --suite "$suite" --endpoint "$EP" --model "$MODEL" \
  --grant-source planner --planner-grants evaluation/agentdojo/planner/grants \
  --binary target/debug/attenuo-server
```

## Layout

Each `<suite>/` directory has two arms.

`baseline/`, the output of `pilot.py` for this suite:
- `results-<suite>-0.json`
- `usage-<suite>-0.jsonl`
- `logs/qwen2.5:14b-16k/<suite>/…`: one AgentDojo log per run
- `console.log`: the runner's stdout and stderr

`enforced/`, the output of `enforced.py`:
- `decisions-grants-0.jsonl`: attenuo's decision on every tool call
- `lists-decisions-grants-0.jsonl`
- `usage-grants-0.jsonl`
- `errors.jsonl`
- `logs/qwen2.5:14b-16k-attenuo-grants/<suite>/…`: one AgentDojo log per run
- `console.log`

The runner's `work-*` directory is left out of `enforced/`. It holds the generated server config, Cedar policy and server log, which contain local paths. The config and policy are generated from the committed grants and suite policy by `enforced.py`.

Errored runs: a run that the model server aborted has a line in `errors.jsonl` (or in the baseline's `results-<suite>-0.json` `errors` and `console.log`). Its per-run log has `utility` and `security` set to null. Count these runs apart; they are neither successes nor failures. Every error so far is Ollama's `500 prediction aborted, token repeat limit reached`, where the model repeated itself until the server stopped it.

## Runs

| Suite | Arm | Start (UTC) | End (UTC) | Runs | Errored | Benign utility (scored) | Attacks succeeded (scored attack runs) | Utility under attack |
|---|---|---|---|---|---|---|---|---|
| slack | baseline | 2026-11-12 19:05:07 | 20:47:35 | 126 | 1 (attack) | 10/21 | 78/104 | 46/104 |
| slack | attenuo, planner grants | 2026-11-12 20:47:35 | 22:11:20 | 126 | 7 (1 benign, 6 attack) | 8/20 | 15/99 | 26/99 |

Counts are read from the per-run logs; errored runs (null scores) are excluded from both numerator and denominator.
