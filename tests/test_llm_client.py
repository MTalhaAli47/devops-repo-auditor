
import json

from llm_client import GeminiClient


class FakeInteraction:
    def __init__(self, payload):
        self.payload = payload
        self.id = payload.get("id")
        self.status = payload.get("status", "completed")

    def model_dump(self, exclude_none=True):
        return self.payload


class FakeInteractions:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return FakeInteraction(next(self.responses))

    def get(self, interaction_id):
        raise AssertionError("No polling expected for completed responses")


class FakeGenAI:
    def __init__(self, responses):
        self.interactions = FakeInteractions(responses)


def test_tool_loop_calls_tool_and_returns_final_text():
    first_response = {
        "id": "interaction-1",
        "status": "completed",
        "steps": [
            {
                "type": "function_call",
                "id": "call-1",
                "name": "list_files",
                "arguments": {"subdirectory": "."},
            }
        ],
    }

    second_response = {
        "id": "interaction-2",
        "status": "completed",
        "output_text": '{"repository":"example","violations":[]}',
        "steps": [],
    }

    client = GeminiClient.__new__(GeminiClient)
    client.model = "test-model"
    client.max_wait_seconds = 5
    client.client = FakeGenAI([first_response, second_response])

    observed = []

    def fake_list_files(subdirectory="."):
        observed.append(subdirectory)
        return {"files": ["README.md"], "count": 1}

    output = client.run_with_tools(
        prompt="Inspect this test repository.",
        tool_schemas=[
            {
                "type": "function",
                "name": "list_files",
                "description": "List repository files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "subdirectory": {"type": "string"}
                    },
                },
            }
        ],
        tool_handlers={"list_files": fake_list_files},
    )

    assert observed == ["."]
    assert json.loads(output)["violations"] == []

    requests = client.client.interactions.requests
    assert len(requests) == 2
    assert requests[1]["previous_interaction_id"] == "interaction-1"
    assert requests[1]["input"][0]["type"] == "function_result"
    assert "README.md" in requests[1]["input"][0]["result"][0]["text"]


def test_tool_loop_returns_text_without_calling_tools():
    response = {
        "id": "interaction-1",
        "status": "completed",
        "output_text": '{"repository":"healthy","violations":[]}',
        "steps": [],
    }

    client = GeminiClient.__new__(GeminiClient)
    client.model = "test-model"
    client.max_wait_seconds = 5
    client.client = FakeGenAI([response])

    output = client.run_with_tools(
        prompt="Audit repository.",
        tool_schemas=[],
        tool_handlers={},
    )

    assert json.loads(output)["repository"] == "healthy"
    assert len(client.client.interactions.requests) == 1
