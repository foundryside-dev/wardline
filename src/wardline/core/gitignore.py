"""Stdlib-only ``.gitignore`` matcher for trusted directory-pruning callers.

This is a *pruning* matcher: callers use it to decide whether to descend into a
directory during ``os.walk``. Wardline's normal source discovery deliberately does
not honor repository ``.gitignore`` files, because those files are checkout content
and can hide tracked source. The matcher remains available for explicit trusted
opt-in paths. It implements the subset of the gitignore spec that governs
*directory* decisions deterministically:

* blank lines and ``#`` comments are ignored;
* a leading ``!`` negates (un-ignores) a later-matched pattern;
* a leading ``/`` anchors the pattern to the directory holding the ``.gitignore``;
* a trailing ``/`` restricts the pattern to directories;
* ``*`` matches within a path segment, ``?`` matches one non-``/`` char, and a
  leading ``**/`` matches in any directory;
* later patterns win (git's last-match-wins ordering), with negation honoured.

Patterns are accumulated per-directory as the top-down walk descends, exactly as git
layers nested ``.gitignore`` files. The matcher is intentionally conservative: it is
used ONLY for directory decisions, never to drop individual analyzable files after
discovery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class _Pattern:
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool
    base: str


def _translate(pattern: str) -> str:
    """Translate one gitignore glob body (no anchor/dir/negation markers) to a regex
    matching a single relative POSIX path with no leading slash."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # ``**`` — span across path separators.
                j = i + 2
                if j < n and pattern[j] == "/":
                    out.append("(?:.*/)?")
                    i = j + 1
                    continue
                out.append(".*")
                i = j
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                # Unterminated class — treat ``[`` literally.
                out.append(re.escape("["))
                i += 1
                continue
            cls = pattern[i + 1 : j]
            if cls.startswith("!"):
                cls = "^" + cls[1:]
            out.append("[" + cls + "]")
            i = j + 1
            continue
        out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _compile(raw: str, *, base: str = "") -> _Pattern | None:
    line = raw.rstrip("\n")
    # A trailing backslash escapes a space; otherwise trailing whitespace is trimmed.
    if not line.endswith("\\ "):
        line = line.rstrip()
    if not line or line.startswith("#"):
        return None
    negated = False
    if line.startswith("!"):
        negated = True
        line = line[1:]
    if line.startswith("\\#") or line.startswith("\\!"):
        line = line[1:]
    dir_only = line.endswith("/")
    if dir_only:
        line = line[:-1]
    if not line:
        return None
    anchored = line.startswith("/")
    has_internal_slash = "/" in line.strip("/")
    if anchored:
        line = line[1:]
    body = _translate(line)
    if anchored or has_internal_slash:
        # Anchored to the .gitignore's directory: match from the relative root.
        regex = re.compile(r"\A" + body + r"\Z")
    else:
        # A bare name matches at any depth (git matches the basename anywhere).
        regex = re.compile(r"(?:\A|/)" + body + r"\Z")
    return _Pattern(regex=regex, negated=negated, dir_only=dir_only, base=base)


@dataclass(frozen=True, slots=True)
class GitignoreMatcher:
    """An ordered, layered set of gitignore patterns rooted at a base directory."""

    _patterns: tuple[_Pattern, ...]

    @classmethod
    def empty(cls) -> GitignoreMatcher:
        return cls(_patterns=())

    @classmethod
    def from_text(cls, text: str, *, base: str = "") -> GitignoreMatcher:
        base = "" if base in (".", "/") else base.strip("/")
        compiled = tuple(p for p in (_compile(line, base=base) for line in text.splitlines()) if p is not None)
        return cls(_patterns=compiled)

    @classmethod
    def from_file(cls, path: Path, *, base: str = "") -> GitignoreMatcher:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return cls.empty()
        return cls.from_text(text, base=base)

    def extend(self, other: GitignoreMatcher) -> GitignoreMatcher:
        """Layer ``other``'s patterns AFTER this matcher's (later wins, git ordering)."""
        if not other._patterns:
            return self
        if not self._patterns:
            return other
        return GitignoreMatcher(_patterns=self._patterns + other._patterns)

    def __bool__(self) -> bool:
        return bool(self._patterns)

    def match(self, relposix: str, *, is_dir: bool) -> bool:
        """Return whether ``relposix`` (a POSIX path relative to the matcher base) is
        ignored. Last matching pattern wins; a negation un-ignores."""
        ignored = False
        matched = False
        for pat in self._patterns:
            if pat.dir_only and not is_dir:
                continue
            if pat.base:
                if not relposix.startswith(pat.base + "/"):
                    continue
                candidate = relposix.removeprefix(pat.base + "/")
            else:
                candidate = relposix
            if pat.regex.search(candidate):
                matched = True
                ignored = not pat.negated
        if not matched:
            return False
        return ignored
