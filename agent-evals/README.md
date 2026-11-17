# Cross-agent feature quality pilot

Same repository-owned feature-to-test contract for Codex, Claude Code, ChatGPT, Copilot and local agents.
Small curated subset of code; existing project architecture and Android CI remain authoritative.

Run python3 scripts/agent_feature_map.py validate and
python3 -m unittest discover -s scripts -p test_agent_feature_map.py.
For PR impact run python3 scripts/agent_feature_map.py impact --base BASE --head HEAD.

A mapped change suggests existing regression tests; it DOES NOT execute those tests.
Unmapped Kotlin paths are visible, and unrun automated/physical evidence remains NOT RUN.
For confirmed defects: reproduce the original failure, add a pre-fix failing test,
fix the issue, then verify exact-commit Android CI and record separate physical evidence.
Mapping counts are NOT quality statistics; use verified repeated matched trials
before drawing model-performance conclusions. Product field acceptance: docs/TEST_STRATEGY.md.
