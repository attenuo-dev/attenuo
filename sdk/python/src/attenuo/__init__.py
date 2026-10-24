"""Python SDK for the attenuo authorization server.

from attenuo import Client, AdminClient, Capability, Prefix, Denied

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

from ._wire import Approval, AuthzenDecision, Lease, Tool, ToolResult
from .admin import (
    AdminClient,
    AsyncAdminClient,
    AuditEntry,
    AuditEntryDetail,
    AuditFilter,
    AuditPage,
    CheckpointPage,
    LeaseNode,
    LeaseState,
    LeaseStatus,
    LeaseTree,
    PolicyCheck,
    PolicyEvaluation,
    PolicyReload,
    PolicySet,
    RevokeResult,
    SelectorRevocation,
    VerifyReport,
)
from .approval import (
    APPROVAL_TOKEN_TYPE,
    META_APPROVAL_KEY,
    ApprovalClaims,
    call_hash,
    verify_approval_token,
)
from .capability import ArgLimit, Capability, Equals, Limits, OneOf, Prefix
from .client import AsyncClient, Client
from .dpop import DpopKey
from .errors import (
    ApiError,
    ApprovalNotGranted,
    ApprovalRequired,
    AttenuoError,
    Denied,
    RefreshError,
    RpcError,
    Unauthorized,
    VerificationError,
)
from .refresh import AsyncTokenRefresher, TokenRefresher
from .token import Chain, Hop, Token, User, decode_token, verify_token

try:
    __version__ = version("attenuo")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "APPROVAL_TOKEN_TYPE",
    "META_APPROVAL_KEY",
    "AdminClient",
    "ApiError",
    "Approval",
    "ApprovalClaims",
    "ApprovalNotGranted",
    "ApprovalRequired",
    "ArgLimit",
    "AsyncAdminClient",
    "AsyncClient",
    "AsyncTokenRefresher",
    "AttenuoError",
    "AuditEntry",
    "AuditEntryDetail",
    "AuditFilter",
    "AuditPage",
    "AuthzenDecision",
    "Capability",
    "Chain",
    "CheckpointPage",
    "Client",
    "Denied",
    "DpopKey",
    "Equals",
    "Hop",
    "Lease",
    "LeaseNode",
    "LeaseState",
    "LeaseStatus",
    "LeaseTree",
    "Limits",
    "OneOf",
    "PolicyCheck",
    "PolicyEvaluation",
    "PolicyReload",
    "PolicySet",
    "Prefix",
    "RefreshError",
    "RevokeResult",
    "RpcError",
    "SelectorRevocation",
    "Token",
    "TokenRefresher",
    "Tool",
    "ToolResult",
    "Unauthorized",
    "User",
    "VerificationError",
    "VerifyReport",
    "call_hash",
    "decode_token",
    "verify_approval_token",
    "verify_token",
]
