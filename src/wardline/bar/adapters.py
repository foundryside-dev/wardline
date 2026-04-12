"""Reviewer adapter protocol and optional live BAR adapter."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_VALID_VERDICTS = frozenset({"pass", "fail", "insufficient_evidence", "refer"})


@dataclass(frozen=True)
class ReviewerResult:
    """Structured reviewer output captured by the BAR runner."""

    verdict: Literal["pass", "fail", "insufficient_evidence", "refer"]
    rationale: str
    citations: tuple[str, ...] = ()
    raw_citations: tuple[str, ...] = ()
    raw_response: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in _VALID_VERDICTS:
            raise ValueError(f"invalid BAR reviewer verdict {self.verdict!r}")
        object.__setattr__(self, "citations", tuple(self.citations))
        object.__setattr__(
            self,
            "raw_citations",
            tuple(self.raw_citations) if self.raw_citations else tuple(self.citations),
        )


class ReviewerAdapter(Protocol):
    """Protocol implemented by BAR reviewer backends."""

    def review(self, *, role: str, prompt: str, model_pin: Mapping[str, object]) -> ReviewerResult:
        """Run one BAR reviewer role against one rendered prompt."""


class LiteLLMReviewerAdapter:
    """Optional live BAR adapter backed by LiteLLM completion()."""

    def __init__(self, completion_func: Callable[..., object]) -> None:
        self._completion = completion_func

    def review(self, *, role: str, prompt: str, model_pin: Mapping[str, object]) -> ReviewerResult:
        completion = cast("Any", self._completion)
        timeout_seconds = _float_value(model_pin.get("timeout_seconds"), default=180.0)
        max_retries = _int_value(model_pin.get("max_retries"), default=1)
        max_attempts = max_retries + 1
        last_exc: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                response = completion(
                    model=str(model_pin["model_id"]),
                    max_tokens=_int_value(model_pin.get("max_output_tokens"), default=16384),
                    temperature=_float_value(model_pin.get("temperature"), default=0.0),
                    top_p=_float_value(model_pin.get("top_p"), default=1.0),
                    timeout=timeout_seconds,
                    messages=[{"role": "user", "content": prompt}],
                )
                last_exc = None
                break
            except Exception as exc:  # pragma: no cover - live provider path
                last_exc = exc
                if attempt >= max_attempts:
                    break
        else:  # pragma: no cover - loop exits via break or final failure
            last_exc = None

        if last_exc is not None:
            failure_kind = _transport_failure_kind(last_exc)
            return ReviewerResult(
                verdict="insufficient_evidence",
                rationale=(
                    f"BAR adapter {failure_kind} for role {role} after {max_attempts} attempt(s) "
                    f"(timeout={timeout_seconds}s, retries={max_retries}): "
                    f"{type(last_exc).__name__}: {last_exc}"
                ),
            )

        try:
            raw_response = _response_text(response)
        except Exception as exc:  # pragma: no cover - defensive path
            return ReviewerResult(
                verdict="insufficient_evidence",
                rationale=(
                    f"BAR adapter response-shape failure for role {role}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
        parsed = _parse_reviewer_response(raw_response)
        return ReviewerResult(
            verdict=parsed.verdict,
            rationale=parsed.rationale,
            citations=parsed.citations,
            raw_response=raw_response,
        )


# Backwards-compatibility alias for any in-repo or external imports that still
# reference the old provider-specific name.
AnthropicReviewerAdapter = LiteLLMReviewerAdapter


def _response_text(response: object) -> str:
    if isinstance(response, dict):
        return _response_text_from_choice_container(response.get("choices"), fallback=response)

    choices = getattr(response, "choices", None)
    if choices is not None:
        return _response_text_from_choice_container(choices, fallback=response)

    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return str(response)

    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts).strip()


def _response_text_from_choice_container(choices: object, *, fallback: object) -> str:
    if not isinstance(choices, list) or not choices:
        return str(fallback)

    first_choice = choices[0]
    message = first_choice.get("message") if isinstance(first_choice, dict) else getattr(first_choice, "message", None)
    content = message.get("content") if isinstance(message, dict) else getattr(message, "content", None)

    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return _join_content_parts(content)
    return str(fallback)


def _join_content_parts(parts: list[object]) -> str:
    text_parts: list[str] = []
    for part in parts:
        text = part.get("text") if isinstance(part, dict) else getattr(part, "text", None)
        if isinstance(text, str):
            text_parts.append(text)
    return "\n".join(text_parts).strip()


def _parse_reviewer_response(raw_response: str) -> ReviewerResult:
    match = re.match(
        r"\s*VERDICT:\s*(pass|fail|insufficient_evidence|refer)\s*\n+"
        r"\s*RATIONALE:\s*(.*?)\n+"
        r"\s*CITATIONS:\s*(.*)\Z",
        raw_response,
        flags=re.DOTALL,
    )
    if match is None:
        return ReviewerResult(
            verdict="insufficient_evidence",
            rationale=(
                "BAR adapter returned a response that did not follow the required "
                "VERDICT/RATIONALE/CITATIONS format."
            ),
            citations=(),
            raw_response=raw_response,
        )

    rationale = match.group(2).strip()
    citations = _parse_citation_block(match.group(3))
    return ReviewerResult(
        verdict=cast("Literal['pass', 'fail', 'insufficient_evidence', 'refer']", match.group(1)),
        rationale=rationale,
        citations=citations,
        raw_citations=citations,
        raw_response=raw_response,
    )


def _parse_citation_block(citation_block: str) -> tuple[str, ...]:
    citations: list[str] = []
    seen: set[str] = set()

    citation_block = _strip_fenced_code_blocks(citation_block)
    for match in re.finditer(r"(?<!`)`([^`\n]+)`(?!`)", citation_block):
        citation = match.group(1).strip()
        if citation and citation not in seen:
            citations.append(citation)
            seen.add(citation)

    return tuple(citations)


def _transport_failure_kind(exc: Exception) -> str:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if "timeout" in name or "timed out" in message or "timeout" in message:
        return "timeout"
    return "transport failure"


def _strip_fenced_code_blocks(rationale: str) -> str:
    return re.sub(r"```.*?```", "", rationale, flags=re.DOTALL)


def _int_value(value: object, *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, (float, str)):
        return int(value)
    return default


def _float_value(value: object, *, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    return default
