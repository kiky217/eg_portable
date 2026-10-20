# EG v3.1.74 — isolated local regression evidence

- Date: 2026-10-20 UTC
- Canonical source: `882a1eb331b7db9ca90b3b4a0d8210232d0f95e8`; official `v3.1.74` source artifact from CI run `39505667528`, SHA-matched to main Git tree.
- Runtime: isolated local Python 3.13, `PYTHONPATH=.:tests`, full source archive (not reduced portable subset); no RD MCP/KNID-PC.
- Test partition A: `python -m pytest -q -p no:cacheprovider tests/test_hardening.py tests/test_v3_regressions.py tests/test_cutover_readiness.py tests/test_post_cutover_readiness.py tests/test_notary_domain_e2e.py tests/test_admission_integrity_and_resume.py` → **124 passed**, exit 0, 24.55 s.
- Test partition B: `python -m pytest -q -p no:cacheprovider tests` **excluding exactly the six files above via `--ignore`** → **369 passed, 4 skipped**, terminal log 34.04 s. Wrapper tool response timed out after child had completed; log recorded terminal pytest summary and process reconciliation found no active pytest PID.
- **Aggregate disjoint suite: 493 passed, 4 skipped, 0 failed**. Additional focused GitHub RPC and cross-UID E3/E4 sandbox checks PASS.
- GitHub CI `39505667528`: validate SUCCESS, publish_stable SUCCESS; release tag pinned exact main SHA.
- This evidence is a test/release acceptance only, **not** proof of independent production external GitHub operator authorization, physical E4 mutation or live canonical POST `SATISFIED`. #61/#68/#104 remain open for those separate acceptance criteria.
- This evidence file is documentation only. Its commit postdates the tested source; it does not alter runtime source.
