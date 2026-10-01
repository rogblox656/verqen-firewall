"""Run the bundled injection dataset through verqen-firewall and record metrics.

Usage::

    python benchmarks/run_benchmark.py --checkpoint "$VERQEN_CHECKPOINT"
    python benchmarks/run_benchmark.py --policy pii --limit 20 --fail-under 0.9

Loads ``injection_dataset.jsonl`` (48 injection cases across 6 categories plus
48 benign controls), checks every text with a live firewall, and writes a JSON
report to ``benchmarks/results/`` with:

* overall accuracy, injection recall, benign pass rate
* per-category injection recall
* latency p50 / p95 (includes deterministic pre-filter + model)

The bundled dataset is a starter regression suite. The official VerQen
benchmark numbers in the README come from the full Jev-Parity eval suite.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DATASET = HERE / "injection_dataset.jsonl"
RESULTS_DIR = HERE / "results"

sys.path.insert(0, str(HERE.parent))  # allow running without pip install

from verqen_firewall import VerQenFirewall  # noqa: E402


def load_dataset(path: Path = DEFAULT_DATASET) -> list[dict]:
    """Load and validate the JSONL dataset (fields: id, text, label, category)."""
    rows: list[dict] = []
    with open(path, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            missing = {"id", "text", "label", "category"} - row.keys()
            if missing:
                raise ValueError(f"{path.name}:{lineno}: missing fields {sorted(missing)}")
            if row["label"] not in ("injection", "benign"):
                raise ValueError(f"{path.name}:{lineno}: bad label {row['label']!r}")
            rows.append(row)
    if not rows:
        raise ValueError(f"{path.name}: dataset is empty")
    return rows


def check_row(firewall: VerQenFirewall, row: dict) -> dict:
    """Run one dataset row through the firewall and time it."""
    start = time.perf_counter()
    result = firewall.check(row["text"])
    elapsed_ms = (time.perf_counter() - start) * 1000
    predicted = "benign" if result.safe else "injection"
    return {
        "id": row["id"],
        "label": row["label"],
        "category": row["category"],
        "predicted": predicted,
        "correct": predicted == row["label"],
        "detected_severity": result.severity,
        "confidence": round(result.confidence, 4),
        "latency_ms": round(elapsed_ms, 3),
    }


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile (p in 0..100); 0.0 for an empty list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), -(-int(p * len(ordered)) // 100)))
    return ordered[rank - 1]


def summarize(records: list[dict]) -> dict:
    """Aggregate per-record results into a metrics report."""
    total = len(records)
    if total == 0:
        raise ValueError("no records to summarize")
    correct = sum(1 for r in records if r["correct"])
    injection = [r for r in records if r["label"] == "injection"]
    benign = [r for r in records if r["label"] == "benign"]
    detected = sum(1 for r in injection if r["predicted"] == "injection")
    passed = sum(1 for r in benign if r["predicted"] == "benign")

    by_category: dict[str, list[dict]] = {}
    for record in injection:
        by_category.setdefault(record["category"], []).append(record)

    latencies = [r["latency_ms"] for r in records]
    return {
        "total": total,
        "accuracy": round(correct / total, 4),
        "injection_recall": round(detected / len(injection), 4) if injection else None,
        "benign_pass_rate": round(passed / len(benign), 4) if benign else None,
        "per_category_recall": {
            name: round(sum(1 for r in rows if r["correct"]) / len(rows), 4)
            for name, rows in sorted(by_category.items())
        },
        "label_counts": dict(Counter(r["label"] for r in records)),
        "latency_ms": {
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "max": round(max(latencies), 3),
        },
        "errors": [r["id"] for r in records if not r["correct"]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--checkpoint", default=None, help="VerQen checkpoint path")
    parser.add_argument("--policy", default="owasp_llm", help="policy pack (default: owasp_llm)")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--limit", type=int, default=0, help="only run the first N rows")
    parser.add_argument("--fail-under", type=float, default=None,
                        help="exit 3 when overall accuracy is below this value")
    args = parser.parse_args(argv)

    rows = load_dataset(args.dataset)
    if args.limit > 0:
        rows = rows[: args.limit]

    try:
        firewall = VerQenFirewall(checkpoint=args.checkpoint, policy=args.policy)
    except (ValueError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    started = time.time()
    records = []
    for index, row in enumerate(rows, start=1):
        records.append(check_row(firewall, row))
        if index % 20 == 0 or index == len(rows):
            print(f"  {index}/{len(rows)}", flush=True)

    report = {
        "dataset": str(args.dataset.name),
        "policy": args.policy,
        "rows": len(records),
        "wall_seconds": round(time.time() - started, 2),
        "metrics": summarize(records),
        "records": records,
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_path = RESULTS_DIR / f"benchmark-{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    metrics = report["metrics"]
    print()
    print(f"dataset      {report['dataset']} ({report['rows']} rows)")
    print(f"accuracy     {metrics['accuracy']:.1%}")
    print(f"injection    {metrics['injection_recall']}")
    print(f"benign pass  {metrics['benign_pass_rate']}")
    print(f"latency p50  {metrics['latency_ms']['p50']} ms  p95 {metrics['latency_ms']['p95']} ms")
    print(f"report       {out_path}")
    if metrics["errors"]:
        print(f"misses ({len(metrics['errors'])}): {', '.join(metrics['errors'][:20])}")

    if args.fail_under is not None and metrics["accuracy"] < args.fail_under:
        print(
            f"FAIL: accuracy {metrics['accuracy']:.3f} < {args.fail_under:.3f}",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
