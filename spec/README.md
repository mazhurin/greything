# GreyThing Protocol Specifications

These specifications describe the GreyThing protocol as implemented in the reference implementation (March 2026).

## Protocol Scope

GreyThing defines protocols for:

- portable digital identity based on decentralized identifiers
- user-owned storage of content-addressed objects
- capability-based authorization using signed grants
- claims-based identity discovery
- secure interaction between applications, services and automated agents

GreyThing intentionally separates identity, storage and authorization into independent protocol components.

Applications built on GreyThing may implement messaging, publishing, marketplaces or other services using these building blocks.

---

## Non-Goals

GreyThing does not attempt to define:

- a global social network
- a single application or platform
- mandatory federation between servers
- a global blockchain or consensus layer

GreyThing focuses instead on reusable protocol components that independent applications and services can adopt.

## Specifications

| Spec | Description |
|------|-------------|
| [identity-v1.md](identity-v1.md) | DID-based identity, key types, DID Documents, authentication, discovery |
| [storage-v1.md](storage-v1.md) | Content-addressed blobs, mutable heads (CAS), anonymous inbox, ACL |
| [grants-v1.md](grants-v1.md) | Signed capability grants, grant-based blob access |
| [discovery-v1.md](discovery-v1.md) | Claims-based identity discovery, search, privacy-preserving lookup |
| [messaging-v1.md](messaging-v1.md) | End-to-end encrypted messaging with file attachments |
| [email-verification-v1.md](email-verification-v1.md) | Email verification for DID registration, signed attestations |

## How They Fit Together

```
identity-v1          Who you are. DID, keys, service endpoints.
    │
    ▼
storage-v1           Where your data lives. Blobs, heads, inbox.
    │
    ▼
grants-v1            Who can access your data. Signed capabilities.
    │
    ▼
discovery-v1         How others find you. Claims, search, lookup.
    │
    ▼
messaging-v1         Demonstration application using all layers.
    │
    ▼
email-verification-v1  Anti-spam gate for registration.
```

Identity is independent from storage. Storage is independent from applications. Grants bridge the two — they let resource owners authorize specific identities to access specific data.

Messaging is one application built on this stack. Other applications can reuse identity, storage, and grants independently.

## Design Principles

- **Portable identity** — anchored in cryptographic keys, not domains
- **Durable identity** — key rotation, revocation and recovery ensure identities survive device loss
- **User-owned storage** — migratable across providers
- **Capability-based access** — signed grants authorize access to specific resources
- **Privacy by default** — servers see only ciphertext and opaque hashes
- **Protocol-first** — specifications designed for reuse across applications
- **Services as consumers** — services and agents retrieve user-authorized data rather than owning it

## Status

All specifications are **draft** and subject to change. They document the current working implementation rather than a finalized standard.

## Reference Implementation

- **Go backend**: `internal/gtcore/` (storage API, grants, inbox)
- **Browser frontend**: `www/did/index.html` (messaging, encryption, grant creation)
- **WordPress plugin**: `wp-plugin/gt-storage/` (storage + identity hosting)
- **Live demo**: [did.greything.com](https://did.greything.com)

## Cryptographic Primitives

| Primitive | Usage |
|-----------|-------|
| Ed25519 | Identity keys, message signing, grant signing, request authentication |
| X25519 | Key agreement for message and attachment encryption |
| AES-256-GCM | Symmetric encryption (messages, attachments, key wrapping) |
| HKDF-SHA256 | Key derivation from ECDH shared secrets |
| SHA-256 | Content addressing, canonical form hashing |

## License

These specifications are released as part of the GreyThing open infrastructure project under a free and open-source license.
