"""Tests for BAR live-adapter parsing and call plumbing."""

from __future__ import annotations

from wardline.bar.adapters import LiteLLMReviewerAdapter


def test_litellm_reviewer_adapter_calls_completion_and_parses_response() -> None:
    calls: list[dict[str, object]] = []

    def fake_completion(**kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            "VERDICT: pass\n"
                            "RATIONALE: The implementation and cited clause align.\n"
                            "CITATIONS:\n"
                            "- `src/example_impl.py`\n"
                            "- `source_ref:§15.2(5)`"
                        )
                    }
                }
            ]
        }

    adapter = LiteLLMReviewerAdapter(fake_completion)

    result = adapter.review(
        role="python-engineer",
        prompt="review prompt",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "max_output_tokens": 2048,
            "temperature": 0,
            "top_p": 1,
        },
    )

    assert calls == [
        {
            "model": "openrouter/anthropic/claude-opus-4.6",
            "max_tokens": 2048,
            "temperature": 0.0,
            "top_p": 1.0,
            "timeout": 180.0,
            "messages": [{"role": "user", "content": "review prompt"}],
        }
    ]
    assert result.verdict == "pass"
    assert result.rationale == "The implementation and cited clause align."
    assert result.citations == (
        "src/example_impl.py",
        "source_ref:§15.2(5)",
    )
    assert result.raw_citations == result.citations


def test_litellm_reviewer_adapter_ignores_fenced_code_and_unquoted_paths() -> None:
    def fake_completion(**kwargs: object) -> dict[str, object]:
        del kwargs
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            "VERDICT: fail\n"
                            "RATIONALE: See the grounded tokens and ignore the example block.\n"
                            "CITATIONS:\n"
                            "- `source_ref:§15.2(5)`\n"
                            "```python\n"
                            "print('not a citation block')\n"
                            "```\n"
                            "- src/example_impl.py"
                        )
                    }
                }
            ]
        }

    adapter = LiteLLMReviewerAdapter(fake_completion)

    result = adapter.review(
        role="python-engineer",
        prompt="review prompt",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "max_output_tokens": 2048,
            "temperature": 0,
            "top_p": 1,
        },
    )

    assert result.verdict == "fail"
    assert result.citations == ("source_ref:§15.2(5)",)
    assert result.raw_citations == ("source_ref:§15.2(5)",)


def test_litellm_reviewer_adapter_requires_citations_section() -> None:
    def fake_completion(**kwargs: object) -> dict[str, object]:
        del kwargs
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            "VERDICT: pass\n"
                            "RATIONALE: Missing the explicit citations section."
                        )
                    }
                }
            ]
        }

    adapter = LiteLLMReviewerAdapter(fake_completion)

    result = adapter.review(
        role="python-engineer",
        prompt="review prompt",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "max_output_tokens": 2048,
            "temperature": 0,
            "top_p": 1,
        },
    )

    assert result.verdict == "insufficient_evidence"
    assert "VERDICT/RATIONALE/CITATIONS format" in result.rationale
    assert result.raw_citations == ()


def test_litellm_reviewer_adapter_retries_once_before_succeeding() -> None:
    calls: list[dict[str, object]] = []
    attempt = 0

    def fake_completion(**kwargs: object) -> dict[str, object]:
        nonlocal attempt
        calls.append(dict(kwargs))
        attempt += 1
        if attempt == 1:
            raise TimeoutError("first call timed out")
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            "VERDICT: pass\n"
                            "RATIONALE: Recovered on retry.\n"
                            "CITATIONS:\n"
                            "- `src/example_impl.py`"
                        )
                    }
                }
            ]
        }

    adapter = LiteLLMReviewerAdapter(fake_completion)

    result = adapter.review(
        role="python-engineer",
        prompt="review prompt",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "max_output_tokens": 2048,
            "temperature": 0,
            "top_p": 1,
            "timeout_seconds": 15,
            "max_retries": 1,
        },
    )

    assert len(calls) == 2
    assert result.verdict == "pass"
    assert result.citations == ("src/example_impl.py",)


def test_litellm_reviewer_adapter_fails_closed_after_guardrail_exhaustion() -> None:
    calls: list[dict[str, object]] = []

    def fake_completion(**kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        raise TimeoutError("provider timed out")

    adapter = LiteLLMReviewerAdapter(fake_completion)

    result = adapter.review(
        role="python-engineer",
        prompt="review prompt",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "max_output_tokens": 2048,
            "temperature": 0,
            "top_p": 1,
            "timeout_seconds": 12,
            "max_retries": 1,
        },
    )

    assert len(calls) == 2
    assert result.verdict == "insufficient_evidence"
    assert "timeout" in result.rationale
    assert "attempt(s)" in result.rationale
