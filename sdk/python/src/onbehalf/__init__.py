"""Python SDK for the onbehalf authorization server.

from onbehalf import Client, AdminClient, Capability, Prefix, Denied

admin = AdminClient("http://127.0.0.1:8080", "admin-token")
root = admin.mint_root_dev("alice", "https://idp.example", "planner", ["github:*"])  # dev only

with Client("http://127.0.0.1:8080") as ob:
    coder = ob.exchange(root, "coder", [Capability("github", "read_file", repo=Prefix("alice/"))])
    try:
        print(ob.call_tool(coder, "github", "read_file", {"repo": "alice/docs"}).text)
    except Denied as d:
        print("denied:", d.reason, d.decision_id)
"""

from importlib.metadata import PackageNotFoundError, version

from ._wire import AuthzenDecision, Lease, Tool, ToolResult
from .admin import (
    AdminClient,
    AsyncAdminClient,
    AuditEntry,
    LeaseStatus,
    PolicyReload,
    RevokeResult,
    VerifyReport,
)
from .capability import Capability, Equals, OneOf, Prefix
from .client import AsyncClient, Client
from .errors import (
    ApiError,
    Denied,
    OnbehalfError,
    RpcError,
    Unauthorized,
    VerificationError,
)
from .token import Chain, Hop, Token, User, decode_token, verify_token

try:
    __version__ = version("onbehalf")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "AdminClient",
    "ApiError",
    "AsyncAdminClient",
    "AsyncClient",
    "AuditEntry",
    "AuthzenDecision",
    "Capability",
    "Chain",
    "Client",
    "Denied",
    "Equals",
    "Hop",
    "Lease",
    "LeaseStatus",
    "OnbehalfError",
    "OneOf",
    "PolicyReload",
    "Prefix",
    "RevokeResult",
    "RpcError",
    "Token",
    "Tool",
    "ToolResult",
    "Unauthorized",
    "User",
    "VerificationError",
    "VerifyReport",
    "decode_token",
    "verify_token",
]
