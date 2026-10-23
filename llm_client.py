
"""Gemini Interactions API client with dynamic tool-calling support."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from google import genai

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

DEFAULT_MODEL = "gemini-3.8-flash"
POLL_INTERVAL_SECONDS = 2
MAX_WAIT_SECONDS = 120
MAX_TOOL_TURNS = 12

FINAL_STATUSES = {"completed", "failed", "cancelled", "incomplete"}


class LLMError(RuntimeError):
    """Raised when Gemini cannot complete a request."""


class GeminiClient:
    """Background-polling client for Gemini's Interactions API."""

    def __init__(
        self,
        model: str | None = None,
        max_wait_seconds: int = MAX_WAIT_SECONDS,
    ) -> None:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()

        if not api_key:
            raise LLMError(
                "GEMINI_API_KEY is missing. Add it to the project's .env file."
            )

        self.model = (
            model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
        ).strip()

        if not self.model:
            raise LLMError("GEMINI_MODEL cannot be empty.")

        if max_wait_seconds < 1:
            raise ValueError("max_wait_seconds must be at least 1.")

        self.max_wait_seconds = max_wait_seconds
        self.client = genai.Client(api_key=api_key)

    @staticmethod
    def _to_dict(interaction: Any) -> dict[str, Any]:
        """Convert an SDK response or dictionary to a dictionary."""
        if isinstance(interaction, dict):
            return interaction

        if hasattr(interaction, "model_dump"):
            try:
                result = interaction.model_dump(exclude_none=True)
                if isinstance(result, dict):
                    return result
            except Exception:
                pass

        return {}

    @staticmethod
    def _get_attribute_or_key(
        interaction: Any,
        payload: dict[str, Any],
        key: str,
    ) -> Any:
        """Read a field from the serialized response or SDK object."""
        value = payload.get(key)
        if value is not None:
            return value
        return getattr(interaction, key, None)

    def _wait_for_interaction(self, interaction: Any) -> dict[str, Any]:
        """
        Wait for completion or return immediately when Gemini requests a tool.

        The caller must process function calls when status is
        'requires_action' and submit their results in a follow-up interaction.
        """
        payload = self._to_dict(interaction)

        interaction_id = self._get_attribute_or_key(
            interaction, payload, "id"
        )

        if not isinstance(interaction_id, str) or not interaction_id:
            raise LLMError(
                "Gemini returned no readable interaction ID. "
                f"Response fields: {sorted(payload.keys())}"
            )

        status = self._get_attribute_or_key(
            interaction, payload, "status"
        )
        deadline = time.monotonic() + self.max_wait_seconds

        while status not in FINAL_STATUSES and status != "requires_action":
            if time.monotonic() >= deadline:
                raise LLMError(
                    f"Gemini interaction timed out after "
                    f"{self.max_wait_seconds} seconds. "
                    f"Last status: {status!r}. "
                    f"Response fields: {sorted(payload.keys())}"
                )

            time.sleep(
                min(
                    POLL_INTERVAL_SECONDS,
                    max(0.0, deadline - time.monotonic()),
                )
            )

            try:
                interaction = self.client.interactions.get(interaction_id)
            except Exception as exc:
                raise LLMError(
                    f"Polling Gemini failed ({type(exc).__name__}). "
                    "Check API access, model availability, and connectivity."
                ) from None

            payload = self._to_dict(interaction)
            status = self._get_attribute_or_key(
                interaction, payload, "status"
            )

            if status is None:
                raise LLMError(
                    "Gemini polling returned no readable status. "
                    f"Response fields: {sorted(payload.keys())}"
                )

        # This is not an error: the model is waiting for tool results.
        if status == "requires_action":
            return payload

        if status != "completed":
            errors = payload.get("errors", [])
            error = payload.get("error")
            details = errors if errors else error

            if isinstance(details, (dict, list, str)):
                details = str(details)[:1000]
            else:
                details = "No error details provided."

            raise LLMError(
                f"Gemini interaction ended with status: {status}. "
                f"Details: {details}"
            )

        return payload

    def _create_and_wait(
        self,
        prompt_or_results: Any,
        *,
        tools: list[dict[str, Any]] | None = None,
        previous_interaction_id: str | None = None,
    ) -> dict[str, Any]:
        """Create one background interaction and wait for its next action."""
        request: dict[str, Any] = {
            "model": self.model,
            "input": prompt_or_results,
            "background": True,
        }

        if tools:
            request["tools"] = tools

        if previous_interaction_id:
            request["previous_interaction_id"] = previous_interaction_id

        try:
            interaction = self.client.interactions.create(**request)
            return self._wait_for_interaction(interaction)
        except LLMError:
            raise
        except Exception as exc:
            # Avoid exposing credentials, prompts, or repository contents.
            raise LLMError(
                f"Gemini request failed ({type(exc).__name__}). "
                "Check API access, model availability, and connectivity."
            ) from None

    @staticmethod
    def _steps(result: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize interaction steps to dictionaries."""
        steps = result.get("steps", [])

        if not isinstance(steps, list):
            return []

        normalized: list[dict[str, Any]] = []

        for step in steps:
            if isinstance(step, dict):
                normalized.append(step)
            elif hasattr(step, "model_dump"):
                try:
                    item = step.model_dump(exclude_none=True)
                    if isinstance(item, dict):
                        normalized.append(item)
                except Exception:
                    continue

        return normalized

    @staticmethod
    def _output_text(result: dict[str, Any]) -> str:
        """Extract text from an interaction response."""
        output_text = result.get("output_text")

        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        chunks: list[str] = []

        for step in GeminiClient._steps(result):
            if step.get("type") in {"text", "message", "model_output"}:
                value = step.get("text")
                if isinstance(value, str):
                    chunks.append(value)

                content = step.get("content", [])
                if isinstance(content, list):
                    for item in content:
                        if (
                            isinstance(item, dict)
                            and item.get("type") == "text"
                            and isinstance(item.get("text"), str)
                        ):
                            chunks.append(item["text"])

        return "\n".join(chunks).strip()

    def generate(self, prompt: str) -> str:
        """Generate a text response without tools."""
        result = self._create_and_wait(prompt)
        text = self._output_text(result)

        if not text:
            raise LLMError(
                "Gemini completed the request without returning text."
            )

        return text

    def run_with_tools(
        self,
        prompt: str,
        tool_schemas: list[dict[str, Any]],
        tool_handlers: dict[str, Callable[..., Any]],
        max_turns: int = MAX_TOOL_TURNS,
    ) -> str:
        """
        Let Gemini select tools, inspect results, and make follow-up calls.

        Tool handlers must validate inputs and remain read-only.
        """
        if not 1 <= max_turns <= MAX_TOOL_TURNS:
            raise ValueError(
                f"max_turns must be between 1 and {MAX_TOOL_TURNS}."
            )

        result = self._create_and_wait(prompt, tools=tool_schemas)

        for _ in range(max_turns):
            function_calls = [
                step
                for step in self._steps(result)
                if step.get("type") == "function_call"
            ]

            if not function_calls:
                text = self._output_text(result)

                if not text:
                    status = result.get("status")
                    raise LLMError(
                        "Gemini returned no final text response. "
                        f"Interaction status: {status!r}; "
                        f"response fields: {sorted(result.keys())}"
                    )

                return text

            function_results: list[dict[str, Any]] = []

            for call in function_calls:
                name = call.get("name")
                call_id = call.get("id") or call.get("call_id")
                arguments = call.get("arguments", {})

                if not isinstance(name, str) or not isinstance(call_id, str):
                    raise LLMError(
                        "Gemini returned a function call without a valid "
                        "name or call ID."
                    )

                if not isinstance(arguments, dict):
                    raise LLMError(
                        f"Gemini supplied invalid arguments for tool '{name}'."
                    )

                handler = tool_handlers.get(name)

                if handler is None:
                    tool_result: Any = {
                        "error": f"Unknown tool: {name}"
                    }
                else:
                    try:
                        tool_result = handler(**arguments)
                    except Exception as exc:
                        # Avoid passing exception details that could contain
                        # repository content or sensitive information.
                        tool_result = {
                            "error": (
                                f"Tool '{name}' failed "
                                f"({type(exc).__name__})."
                            )
                        }

                try:
                    result_json = json.dumps(
                        tool_result,
                        ensure_ascii=False,
                        default=str,
                    )
                except (TypeError, ValueError):
                    result_json = json.dumps({
                        "error": "Tool returned a non-serializable result."
                    })

                function_results.append({
                    "type": "function_result",
                    "name": name,
                    "call_id": call_id,
                    "result": [{
                        "type": "text",
                        "text": result_json,
                    }],
                })

            previous_id = result.get("id")

            if not isinstance(previous_id, str) or not previous_id:
                raise LLMError(
                    "Gemini returned no interaction ID for tool follow-up."
                )

            # Submit tool results and let Gemini decide what to do next.
            result = self._create_and_wait(
                function_results,
                tools=tool_schemas,
                previous_interaction_id=previous_id,
            )

        raise LLMError(
            f"Gemini reached the maximum of {max_turns} tool-calling turns "
            "without finishing the audit."
        )
