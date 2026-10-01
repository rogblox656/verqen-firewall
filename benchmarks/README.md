# Benchmark suite

Runs the bundled `injection_dataset.jsonl` through a live `verqen-firewall`.

```bash
export VERQEN_CHECKPOINT=/path/to/verqen-checkpoint
python benchmarks/run_benchmark.py
python benchmarks/run_benchmark.py --policy pii --limit 20
python benchmarks/run_benchmark.py --fail-under 0.9   # CI gate, exit 3 on failure
```

## Dataset

Starter regression suite: 96 rows (48 injection across `prompt_injection`,
`jailbreak`, `system_override`, `pii_extraction`, `role_override`; 48 benign
controls). Each row:

```json
{"id": "inj-001", "text": "...", "label": "injection", "category": "prompt_injection"}
```

Rows that match a deterministic pre-filter rule are still scored end to end:
the benchmark measures the full pipeline, not just the model.

> The official accuracy numbers in the README (93.1% injection detection)
> come from the full Jev-Parity eval suite run on 2026-09-30, not from this
> smaller starter set. Append your own cases to `injection_dataset.jsonl` to
> expand it; `run_benchmark.py --dataset path/to/your.jsonl` accepts any file
> with the same schema.

## Results

Reports are written to `results/benchmark-<timestamp>.json` (git-ignored
except this README). Fields: `metrics.accuracy`, `injection_recall`,
`benign_pass_rate`, `per_category_recall`, `latency_ms.p50/p95/max`, `errors`
(ids of missed rows), plus every per-row record.
