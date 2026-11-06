"""The package root exports the audit, MCP and DPoP helpers, as the TypeScript SDK's root does."""

from __future__ import annotations

import importlib

import pytest

import attenuo

# Names the TypeScript root (`sdk/typescript/src/index.ts`) exports that have a Python
# equivalent, under their Python spelling, plus the rest of `attenuo.audit.__all__` and
# the DPoP `PROOF_TYPE`, with the submodule that defines each.
ROOT_EXPORTS = {
    "attenuo.audit": [
        "ENTRY_HASH_VERSION",
        "EXPORT_FORMAT",
        "GENESIS_HASH",
        "SHIPPED_FORMAT",
        "BadCheckpoint",
        "CrossCheckReport",
        "ExportError",
        "ExportReport",
        "ShippedLine",
        "ShippedMismatch",
        "cross_check",
        "entry_hash",
        "parse_shipped",
        "verify_export",
    ],
    "attenuo.mcp": ["TokenAuth", "mcp_headers", "mcp_url"],
    "attenuo.dpop": [
        "NONCE_HEADER",
        "PROOF_TYPE",
        "USE_DPOP_NONCE",
        "DpopKey",
        "NonceCache",
        "access_token_hash",
        "is_use_dpop_nonce",
        "jwk_thumbprint",
    ],
    "attenuo.token": ["TOKEN_TYPE"],
    "attenuo.capability": ["capabilities_to_json"],
}

CONSTANTS = {
    "ENTRY_HASH_VERSION",
    "EXPORT_FORMAT",
    "GENESIS_HASH",
    "NONCE_HEADER",
    "PROOF_TYPE",
    "SHIPPED_FORMAT",
    "TOKEN_TYPE",
    "USE_DPOP_NONCE",
}

CASES = [(mod, name) for mod, names in ROOT_EXPORTS.items() for name in names]


@pytest.mark.parametrize(("module", "name"), CASES)
def test_root_exports_the_same_object_as_its_module(module: str, name: str) -> None:
    assert name in attenuo.__all__
    assert getattr(attenuo, name) is getattr(importlib.import_module(module), name)


@pytest.mark.parametrize(("module", "name"), CASES)
def test_root_export_is_a_class_function_or_string(module: str, name: str) -> None:
    obj = getattr(attenuo, name)
    if name in CONSTANTS:
        assert isinstance(obj, str) and obj
    else:
        assert isinstance(obj, type) or callable(obj)


def test_audit_all_is_exported_from_the_root() -> None:
    from attenuo import audit

    assert set(audit.__all__) <= set(attenuo.__all__)


def test_every_name_in_all_resolves() -> None:
    for name in attenuo.__all__:
        assert hasattr(attenuo, name), name


def test_all_has_no_duplicates() -> None:
    assert len(attenuo.__all__) == len(set(attenuo.__all__))
