from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_live_workflow_exercises_both_variants_and_all_modes() -> None:
    workflow = (ROOT / ".github/workflows/live-posting-test.yml").read_text()
    assert "pull_request_target:" in workflow
    assert "variant=naive-a" in workflow
    assert "variant=naive-b" in workflow
    assert "mode=stale" in workflow
    assert "mode=partial" in workflow
    assert "mode=draft" in workflow
    assert "line:999" in workflow
    assert "stale_review_accepted" in workflow
    assert "invalid_second_comment_rejected_atomically" in workflow


def test_production_review_workflows_skip_reserved_live_test_prs() -> None:
    for name in ("agent-review.yml", "agent-review-undefended.yml"):
        workflow = (ROOT / ".github/workflows" / name).read_text()
        assert "startsWith(github.event.pull_request.title, '[live-posting-test]')" in workflow
