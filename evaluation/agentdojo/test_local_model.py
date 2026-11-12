"""The local-model path of pilot.py: endpoint check, request fields, usage log, bad tool JSON."""

import json
from types import SimpleNamespace as NS

import pilot
import pytest
from agentdojo.agent_pipeline import OpenAILLM
from agentdojo.agent_pipeline.llms import openai_llm


def completion(arguments: list[str]):
    calls = [NS(function=NS(name="send_email", arguments=a)) for a in arguments]
    message = NS(tool_calls=calls or None)
    return NS(
        model="qwen2.5:14b",
        usage=NS(prompt_tokens=120, completion_tokens=30),
        choices=[NS(message=message, finish_reason="tool_calls" if calls else "stop")],
    )


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:11434/v1", "http://localhost:8080/v1", "http://[::1]:8000/v1"],
)
def test_a_local_endpoint_is_accepted(url):
    pilot.check_endpoint(url)


@pytest.mark.parametrize(
    "url", ["https://api.example.com/v1", "http://127.0.0.1.example.com/v1", "http://10.0.0.5/v1"]
)
def test_a_remote_endpoint_is_refused(url):
    with pytest.raises(SystemExit):
        pilot.check_endpoint(url)


def test_arguments_that_are_not_a_json_object_become_empty():
    done = completion(['{"to": "a@example.com"}', '{"to": ', "[1, 2]", ""])
    assert pilot.blank_bad_tool_json(done) == 3
    kept = [call.function.arguments for call in done.choices[0].message.tool_calls]
    assert kept == ['{"to": "a@example.com"}', "{}", "{}", "{}"]
    assert pilot.blank_bad_tool_json(completion([])) == 0


def test_the_local_request_is_deterministic_and_metered(tmp_path, monkeypatch):
    monkeypatch.setattr(openai_llm, "chat_completion_request", None)
    meter = pilot.Meter("qwen2.5:14b", 0.0, tmp_path / "usage-x.jsonl")
    meter.task = "slack/user_task_0/none"
    pilot.install_local_meter(meter, 2048)
    sent = {}

    def create(**fields):
        sent.update(fields)
        return completion(["not json"])

    client = NS(chat=NS(completions=NS(create=create)))
    tools = [{"type": "function", "function": {"name": "send_email"}}]
    done = openai_llm.chat_completion_request(client, "qwen2.5:14b", [], tools, None, 0.0)
    assert sent["temperature"] == 0 and sent["seed"] == 0 and sent["max_tokens"] == 2048
    assert sent["tools"] == tools and sent["tool_choice"] == "auto"
    assert done.choices[0].message.tool_calls[0].function.arguments == "{}"
    row = json.loads((tmp_path / "usage-x.jsonl").read_text())
    assert row["task"] == "slack/user_task_0/none"
    assert row["input_tokens"] == 120 and row["output_tokens"] == 30
    assert row["bad_tool_json"] == 1 and row["dollars"] == 0.0
    assert meter.spent() == 0.0

    sent.clear()
    openai_llm.chat_completion_request(client, "qwen2.5:14b", [], [], None, 0.0)
    assert "tools" not in sent and "tool_choice" not in sent


def test_a_local_model_gets_an_openai_element_and_a_name(monkeypatch):
    monkeypatch.delitem(pilot.MODEL_NAMES, "some-local:7b", raising=False)
    llm = pilot.build_llm("some-local:7b", 1024, "http://127.0.0.1:11434/v1")
    assert isinstance(llm, OpenAILLM)
    assert pilot.MODEL_NAMES["some-local:7b"] == pilot.LOCAL_ADDRESS
    pilot.MODEL_NAMES.pop("some-local:7b")
