#!/usr/bin/env python3
"""Summarize terminal native paired v5/v8 runs without making a security claim."""
import argparse
import hashlib
import json
import statistics
from pathlib import Path


def summarize(directory):
    directory = Path(directory)
    status = json.loads((directory / "status.json").read_text())
    assert status["terminal"] and status["exit_code"] == 0
    assert status["proofs"] == 16 and len(status["completed"]) == 8
    provenance = json.loads((directory / "provenance.json").read_text())
    comparisons = []
    for field in ("babybear", "goldilocks"):
        for order in range(2):
            groups = []
            for mode, version in (("deferred", 5), ("shared", 8)):
                name = f"native-{order}-{field}-{mode}"
                data = json.loads((directory / (name + ".json")).read_text())
                assert hashlib.sha256((directory / (name + ".log")).read_bytes()).hexdigest() == data["log_sha256"]
                rows = data["rows"]
                assert len(rows) == 2
                assert all(r["verified"] and r["full_parameters"] and r["protocol_version"] == version and r["verification_scope"] == "complete-serialized-public-verifier" for r in rows)
                groups.append(rows)
            for old, new in zip(*groups):
                for key in ("statement_sha256", "native_keys_sha256", "fhe_parameters_sha256", "width", "lookup_field_degree"):
                    assert old[key] == new[key]
            old, new = [statistics.median(r["complete_ns"] for r in rows) for rows in groups]
            comparisons.append(dict(field=field, order=order, deferred_complete_ns=old,
                                    shared_complete_ns=new, improvement_percent=100*(1-new/old),
                                    deferred_bytes=[r["proof_bytes"] for r in groups[0]],
                                    shared_bytes=[r["proof_bytes"] for r in groups[1]]))
    return dict(scope=provenance["scope"], build_source_sha256=provenance["build_source_sha256"],
                proofs=16, comparisons=comparisons,
                ten_percent_in_both_orders=all(r["improvement_percent"] >= 10 for r in comparisons),
                whole_security_matched=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory), indent=2))
