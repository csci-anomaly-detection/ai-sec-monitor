from datetime import datetime, UTC
from detect import rule_runner
from pathlib import Path

FIXED_NOW = datetime(2025,9,10,10,0,0,tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures" / "logs.ndjson"

def test_rules_trigger():
    alerts = rule_runner.run_all_rules(now=FIXED_NOW, fixture_file=FIXTURES)
    ids = {a["rule_id"] for a in alerts}
    assert ids == {"api_5xx_spike","auth_bruteforce","db_slow_query_storm"}