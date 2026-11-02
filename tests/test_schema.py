"""The JSON report must match schema/report.schema.json."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path
from typing import Any

from glint.cli import main

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "report.schema.json").read_text(encoding="utf-8"))
TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
}


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Validate the subset of JSON Schema used by the report schema."""
    if "$ref" in schema:
        schema = SCHEMA["$defs"][schema["$ref"].rsplit("/", 1)[-1]]
    errors: list[str] = []
    expected = schema.get("type")
    if expected and (not isinstance(value, TYPES[expected]) or (expected == "integer" and isinstance(value, bool))):
        return [f"{path}: expected {expected}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{path}: {value} < {schema['minimum']}")
    if "maximum" in schema and value > schema["maximum"]:
        errors.append(f"{path}: {value} > {schema['maximum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                errors.extend(validate(value[key], sub, f"{path}.{key}"))
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors.extend(validate(item, schema["items"], f"{path}[{i}]"))
    return errors


class SchemaTest(unittest.TestCase):
    def test_reports_match_schema(self) -> None:
        for demo in ("vulnerable-agent", "clean-agent"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["scan", str(ROOT / "demo" / demo), "--format", "json"])
            with self.subTest(demo=demo):
                self.assertEqual(validate(json.loads(out.getvalue()), SCHEMA), [])

    def test_validator_catches_problems(self) -> None:
        self.assertTrue(validate({"tool": "glint"}, SCHEMA))


if __name__ == "__main__":
    unittest.main()
