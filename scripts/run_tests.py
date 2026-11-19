import sys, json, platform, time, unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
start = time.perf_counter()
suite = unittest.defaultTestLoader.discover(
    str(root / "tests"), top_level_dir=str(root)
)
result = unittest.TextTestRunner(verbosity=2).run(suite)
record = {
    "python": sys.version,
    "platform": platform.platform(),
    "tests": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skipped": len(result.skipped),
    "elapsed_seconds": round(time.perf_counter() - start, 3),
    "skip_reasons": [why for _, why in result.skipped],
}
(root / "evidence").mkdir(exist_ok=True)
(root / "evidence/test-results.json").write_text(
    json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
)
sys.exit(not result.wasSuccessful())
