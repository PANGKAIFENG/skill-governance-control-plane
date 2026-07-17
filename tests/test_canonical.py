import json

import pytest
import yaml

from skillctl.canonical import canonical_digest, canonical_json


def test_canonical_json_is_compact_sorted_utf8() -> None:
    assert canonical_json({"z": "\u503c", "a": 1}) == '{"a":1,"z":"\u503c"}'.encode()


def test_digest_is_stable_across_mapping_order_and_json_yaml_sources() -> None:
    from_json = json.loads('{"asset":{"revision":"r1","id":"asset-a"},"enabled":true}')
    from_yaml = yaml.safe_load(
        """
enabled: true
asset:
  id: asset-a
  revision: r1
"""
    )

    assert canonical_digest(from_json) == canonical_digest(from_yaml)


def test_digest_preserves_tuple_order() -> None:
    assert canonical_digest(("asset-a", "asset-b")) != canonical_digest(("asset-b", "asset-a"))


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})
