"""Portable, untrusted capability discovery; a catalog is NOT admission authority."""
import json
import re

_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_EFFECT = frozenset(("E0", "E1", "E2", "E3", "E4", "E5"))

class CatalogError(ValueError):
    pass

def parse_catalog(blob: str) -> tuple[dict, ...]:
    if len(blob.encode("utf-8")) > 131072:
        raise CatalogError("CATALOG_TOO_LARGE")
    try:
        doc = json.loads(blob)
    except (ValueError, TypeError) as exc:
        raise CatalogError("CATALOG_INVALID_JSON") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "capabilities"} or doc["schema_version"] != 1:
        raise CatalogError("CATALOG_INVALID_SCHEMA")
    rows = doc["capabilities"]
    if not isinstance(rows, list) or len(rows) > 128:
        raise CatalogError("CATALOG_INVALID_LENGTH")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "effect_class", "action_type", "adapter_id"}:
            raise CatalogError("CATALOG_INVALID_CAPABILITY")
        if any(not isinstance(row[k], str) or not _NAME.fullmatch(row[k]) for k in ("id", "action_type", "adapter_id")):
            raise CatalogError("CATALOG_INVALID_NAME")
        if row["effect_class"] not in _EFFECT:
            raise CatalogError("CATALOG_INVALID_EFFECT")
        if row["id"] in seen:
            raise CatalogError("CATALOG_DUPLICATE_ID")
        seen.add(row["id"])
    return tuple(rows)

def lookup(rows, effect, action):
    """No claimed adapter can authorize its own execution."""
    return tuple({"capability_id": r["id"], "adapter_id": r["adapter_id"],
                  "trust": "UNVERIFIED", "admission": "NOT_AUTHORIZED"}
                 for r in rows if r["effect_class"] == effect and r["action_type"] == action)
