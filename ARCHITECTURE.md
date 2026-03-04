# GreyThing Architecture

This document describes the **technical architecture** of GreyThing and how its main components interact.

GreyThing explores a shift:

> **From platforms to protocols: letting users own identity and data.**

Instead of platforms owning identity, storage and permissions, GreyThing separates these concerns into independent layers that interact through open protocols.

The architecture enables:

- portable identity
- user-owned storage
- capability-based access control
- services and AI agents interacting with user-authorized data

---

# 1. System Overview

GreyThing separates four fundamental concerns:

1. **Identity Layer** — decentralized identifiers (DID)
2. **Storage Layer** — portable user-owned storage endpoints
3. **Access Layer** — signed capability grants
4. **Service Layer** — applications and agents consuming data

No single layer has global authority.

Services interact with user data but **do not own it**.

---

# 2. Identity Layer

## 2.1 Decentralized Identifiers

GreyThing uses **W3C Decentralized Identifiers (DID)**.

Initial implementation uses `did:web`.

Example:
did:web:greything.com:users:alice


The DID resolves to:
https://greything.com/users/alice/did.json


The DID document is the **root of identity**.

Identity continuity is anchored in cryptographic keys rather than domain ownership.

---

## 2.2 DID Document Contents

A DID Document contains:

- verification keys
- authentication methods
- service endpoints

It does **not** contain:

- private keys
- user content
- personal data

The document only describes **how to interact with the identity**.

---

## 2.3 Cross-Domain Identity Migration

Identity is defined by the **root cryptographic key**, not the hosting domain.

Users may migrate identity by:

- updating DID service endpoints
- linking identities (`alsoKnownAs`)
- optionally redirecting the DID host

This enables **cross-domain identity migration** without losing identity continuity.

---

# 3. Key Architecture

GreyThing uses a multi-tier key model.

## 3.1 Root Identity Key

- Ed25519
- anchors identity
- signs DID updates
- used for recovery

## 3.2 Device Keys

- delegated from root key
- used for daily actions
- stored locally

Device keys sign:

- messages
- grants
- content updates

## 3.3 Backup Keys

Encrypted root key backups may be stored in user storage.

Backups are encrypted client-side.

GreyThing never receives usable private keys.

---

# 4. Storage Layer

GreyThing uses **portable storage endpoints**.

Storage characteristics:

- content-addressed objects
- cryptographic signatures
- provider-independent
- fully migratable

Objects may include:

- content blobs
- encrypted message attachments
- signed grants
- application data

Storage endpoints are referenced from the DID document.

---

# 5. Capability Grants

GreyThing uses **capability-based access control**.

A capability grant is a signed object that authorizes access to a resource.

Example structure:
type: gt.grant.v1
issuer: DID
subject: DID
resource: blob hash
perm: ["read"]
expiresAt: timestamp
signature: Ed25519


Grants allow permissions to be:

- explicit
- verifiable
- portable across services

This differs from server-side ACL systems.

Permissions travel with the request.

---

# 6. Service Layer

Applications interact with GreyThing through open protocols.

Services may include:

- messaging systems
- social feeds
- publishing tools
- marketplaces
- AI agents

Services retrieve **user-authorized data** rather than owning it.

---

# 7. Messaging (Reference Application)

GreyThing includes a **reference messaging implementation**.

Messaging demonstrates how the architecture works in practice.

Features:

- end-to-end encrypted messages
- encrypted attachments
- attachments stored in user storage
- capability grants controlling access

Messaging is a **demonstration application**, not the core infrastructure.

---

# 8. AI Agents

AI agents are treated as **protocol clients**.

Agents may:

- read authorized content
- generate recommendations
- curate feeds
- assist users

Agents interact with user data through:

- capability grants
- open protocols
- user-approved permissions

Agents are replaceable services.

---

# 9. WordPress Nodes

GreyThing includes a WordPress plugin that allows websites to:

- host DID documents
- operate storage endpoints

This demonstrates how existing web infrastructure can participate in decentralized identity and storage systems.

> GreyThing turns ordinary websites into identity and storage nodes.

---

# 10. Example Request Flow

## Reading User Data

1. Resolve user DID
2. Retrieve DID Document
3. Discover storage endpoint
4. Fetch resource with optional capability grant

---

## Sending a Message Attachment

1. Encrypt file client-side
2. Upload encrypted blob to storage
3. Create capability grant for recipient
4. Send encrypted message referencing blob

Recipient:

1. Decrypt message
2. Fetch blob using grant
3. Decrypt attachment

---

## Storage Migration

1. Copy data to new storage endpoint
2. Update DID service endpoint
3. Clients resolve updated DID
4. New storage becomes authoritative

---

# 11. Trust Model

GreyThing minimizes trusted components.

GreyThing infrastructure is trusted only for:

- DID document availability
- protocol correctness

GreyThing is **not trusted for**:

- key custody
- content integrity
- user permissions

Security is based on cryptographic verification.

---

# 12. Failure Modes

## Storage Provider Failure

Users may migrate to another storage provider.

Identity remains intact.

---

## GreyThing Bootstrap Service Failure

Users may migrate their DID hosting to another domain.

Identity continuity is preserved.

---

# 13. Design Goals

GreyThing architecture aims to provide:

- portable identity
- user-owned storage
- verifiable access control
- protocol interoperability
- replaceable services
- long-term resilience

---

# 14. Summary

GreyThing separates:

- identity
- storage
- access control
- services

This enables a protocol-based architecture where:
identity = root key
storage = user owned
permissions = capability grants
services = data consumers


GreyThing provides infrastructure, not platforms.
