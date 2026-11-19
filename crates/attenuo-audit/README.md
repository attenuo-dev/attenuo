# attenuo-audit

The tamper-evident decision log and the lease registry for attenuo.

- **Audit log** (`AuditSink`): every decision record is appended as an entry whose hash covers its sequence number, the previous entry's hash and the record, so editing, reordering or deleting an entry breaks the chain. Checkpoints over the chain head are signed, and an export can be verified offline. `SqliteAudit` persists to a file; `MemoryAudit` is for tests.
- **Leases** (`LeaseStore`): every delegation hop holds a lease. Revoking a lease revokes every lease delegated from it, and an unknown lease is treated as inactive. The store also keeps a run's taint state, approvals and run-limit counters. `LeaseStore` is the sum of five traits, one per concern (`LeaseRegistry`, `RunState`, `ApprovalStore`, `RunLimits`, `StoreRetention`, in the `store` module), so code that needs one concern can take only that trait.

Nothing here evaluates policy.

## In the workspace

It depends on `attenuo-core` and `attenuo-token` (for checkpoint signatures). `attenuo-server` and `attenuo-cli` (`attenuo audit verify --file`) depend on it. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Audit log](https://github.com/attenuo-dev/attenuo/blob/main/docs/concepts/audit-log.md)
- [Leases and revocation](https://github.com/attenuo-dev/attenuo/blob/main/docs/concepts/leases-and-revocation.md)
- [RFC-0001, sections 6 and 7](https://github.com/attenuo-dev/attenuo/blob/main/docs/spec/rfc-0001-attenuo.md#6-revocation-via-leases)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).
