from ordivyr import bench_durable as B


def test_batched_lifecycle_uses_fewer_commits_and_completes_every_task():
    a = B.run(tasks=20, workers=2, steps=3, batch=False); b = B.run(tasks=20, workers=2, steps=3, batch=True)
    assert a["tasks"] == b["tasks"] == 20
    assert b["commits_per_task"] <= a["commits_per_task"] - 2.9      # 3 steps x (output+checkpoint -> 1 commit) saves exactly 3 commits per task
