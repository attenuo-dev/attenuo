"""The package root exports the audit, MCP and DPoP helpers, as the TypeScript SDK's root does."""

from __future__ import annotations

import importlib

import pytest

import attenuo

# Names the TypeScript root (`sdk/typescript/src/index.ts`) exports that have a Python
# equivalent, under their Python spelling, with the submodule that defines each.
ROOT_EXPORTS = {
    "attenuo.audit": [
        "SHIPPED_FORMAT",
        "BadCheckpoint",
        "CrossCheckReport",
        "ExportError",
        "ExportReport",
        "ShippedLine",
        "ShippedMismatch",
        "cross_check",
        "parse_shipped",
        "verify_export",
    ],
    "attenuo.mcp": ["TokenAuth", "mcp_headers", "mcp_url"],
    "attenuo.dpop": [
        "NONCE_HEADER",
        "USE_DPOP_NONCE",
        "DpopKey",
        "NonceCache",
        "access_token_hash",
        "is_use_dpop_nonce",
        "jwk_thumbprint",
    ],
    "attenuo.token": ["TOKEN_TYPE"],
}

CASES = [(mod, name) for mod, names in ROOT_EXPORTS.items() for name in names]


@pytest.mark.parametrize(("module", "name"), CASES)
def test_root_exports_the_same_object_as_its_module(module: str, name: str) -> None:
    assert name in attenuo.__all__
    assert getattr(attenuo, name) is getattr(importlib.import_module(module), name)


def test_every_name_in_all_resolves() -> None:
    for name in attenuo.__all__:
        assert hasattr(attenuo, name), name


def test_all_has_no_duplicates() -> None:
    assert len(attenuo.__all__) == len(set(attenuo.__all__))
