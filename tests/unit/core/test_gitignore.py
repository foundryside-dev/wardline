import shutil
import subprocess
from pathlib import Path

import pytest

from wardline.core.gitignore import GitignoreMatcher


def test_comments_and_blanks_ignored() -> None:
    m = GitignoreMatcher.from_text("# comment\n\n   \nnode_modules/\n")
    assert m.match("node_modules", is_dir=True)
    assert not m.match("node_modules", is_dir=False)  # trailing-slash = dir-only


def test_bare_name_matches_at_any_depth() -> None:
    m = GitignoreMatcher.from_text("node_modules\n")
    assert m.match("node_modules", is_dir=True)
    assert m.match("a/b/node_modules", is_dir=True)


def test_leading_slash_anchors_to_base() -> None:
    m = GitignoreMatcher.from_text("/build\n")
    assert m.match("build", is_dir=True)
    assert not m.match("pkg/build", is_dir=True)


def test_nested_base_scopes_anchored_patterns() -> None:
    m = GitignoreMatcher.from_text("/generated\n", base="pkg")
    assert m.match("pkg/generated", is_dir=True)
    assert not m.match("generated", is_dir=True)
    assert not m.match("pkg/sub/generated", is_dir=True)


def test_internal_slash_anchors() -> None:
    m = GitignoreMatcher.from_text("foo/bar\n")
    assert m.match("foo/bar", is_dir=True)
    assert not m.match("x/foo/bar", is_dir=True)


def test_glob_star_within_segment() -> None:
    m = GitignoreMatcher.from_text("*.egg-info/\n")
    assert m.match("pkg.egg-info", is_dir=True)
    assert m.match("a/b/thing.egg-info", is_dir=True)
    assert not m.match("egg-info", is_dir=True)


def test_double_star_prefix() -> None:
    m = GitignoreMatcher.from_text("**/gen\n")
    assert m.match("gen", is_dir=True)
    assert m.match("a/b/gen", is_dir=True)


def test_negation_last_match_wins() -> None:
    # Last-match-wins at the SAME path. (Re-including a child of an excluded directory
    # is impossible — matching git; covered by test_negation_under_excluded_parent.)
    m = GitignoreMatcher.from_text("logs\n!logs\n")
    assert not m.match("logs", is_dir=True)
    m2 = GitignoreMatcher.from_text("*.tmp\n!keep.tmp\n")
    assert m2.match("x.tmp", is_dir=True)
    assert not m2.match("keep.tmp", is_dir=True)


def test_negation_under_excluded_parent_matches_git() -> None:
    # Git: "It is not possible to re-include a file if a parent directory of that file
    # is excluded." The matcher is faithful — `!vendor/keep` does NOT re-admit a child
    # of an excluded `vendor/`. (Verified against real `git check-ignore`.)
    m = GitignoreMatcher.from_text("vendor/\n!vendor/keep/\n")
    assert m.match("vendor", is_dir=True)


def test_question_mark_single_char() -> None:
    m = GitignoreMatcher.from_text("cache?\n")
    assert m.match("cacheX", is_dir=True)
    assert not m.match("cacheXY", is_dir=True)


def test_unmatched_path_is_not_ignored() -> None:
    m = GitignoreMatcher.from_text("node_modules/\n")
    assert not m.match("src", is_dir=True)


def test_extend_layers_later_patterns() -> None:
    # A later layer's negation overrides an earlier layer AT THE SAME PATH.
    base = GitignoreMatcher.from_text("*.log\n")
    local = GitignoreMatcher.from_text("!keep.log\n")
    layered = base.extend(local)
    assert layered.match("x.log", is_dir=True)
    assert not layered.match("keep.log", is_dir=True)
    # extend is non-mutating: the base alone still ignores keep.log.
    assert base.match("keep.log", is_dir=True)


def test_from_file_missing_is_empty(tmp_path: Path) -> None:
    m = GitignoreMatcher.from_file(tmp_path / "nope.gitignore")
    assert not m
    assert not m.match("anything", is_dir=True)


def test_empty_matcher_falsey() -> None:
    assert not GitignoreMatcher.empty()
    assert not GitignoreMatcher.from_text("# only a comment\n")


def test_character_class() -> None:
    m = GitignoreMatcher.from_text("build[0-9]/\n")
    assert m.match("build3", is_dir=True)
    assert not m.match("buildX", is_dir=True)


def test_repo_gitignore_tracks_wardline_suppression_state() -> None:
    if shutil.which("git") is None:
        pytest.skip("git is required to validate repository ignore policy")
    repo = Path(__file__).resolve().parents[3]
    in_worktree = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
        check=False,
        capture_output=True,
        text=True,
    )
    if in_worktree.returncode != 0:
        pytest.skip("repository ignore policy test requires a git checkout")

    def check_ignore(path: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "--no-index", "-v", path],
            check=False,
            capture_output=True,
            text=True,
        )

    for state_file in (
        ".weft/wardline/baseline.yaml",
        ".weft/wardline/waivers.yaml",
        ".weft/wardline/judged.yaml",
    ):
        result = check_ignore(state_file)
        assert result.returncode == 1, result.stdout + result.stderr

    for sibling_store_file in (
        ".weft/filigree/federation_token",
        ".weft/loomweave/loomweave.db",
        ".weft/warpline/warpline.db",
    ):
        result = check_ignore(sibling_store_file)
        assert result.returncode == 0, result.stdout + result.stderr

    for port_file in (".weft/new-sibling/ephemeral.port",):
        result = check_ignore(port_file)
        assert result.returncode == 0, result.stdout + result.stderr
        assert ".weft/*/ephemeral.port" in result.stdout
