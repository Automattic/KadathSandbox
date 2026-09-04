#!/usr/bin/env python3
"""Minimal validation of iocs.json against the required keys of the schema.
Not a full JSON-schema engine (stdlib only): checks required top-level keys,
the network.observed field, and that every indicator has type+value with an
allowed type. Exit 0 = valid."""
import json
import sys

iocs = json.load(open(sys.argv[1]))
schema = json.load(open(sys.argv[2]))
req = schema["required"]
for k in req:
    assert k in iocs, f"missing {k}"
assert "observed" in iocs["network"]
allowed = set(schema["properties"]["indicators"]["items"]["properties"]["type"]["enum"])
for ind in iocs["indicators"]:
    assert ind["type"] in allowed, f"bad indicator type {ind['type']}"
    assert "value" in ind
print("iocs valid")
