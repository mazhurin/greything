# GreyThing Protocol Overview

This document describes the **core protocol model** used by GreyThing.

GreyThing explores an internet architecture where:

- identity is portable
- storage is user-owned
- permissions are capability-based
- services interact with data through open protocols

GreyThing is **protocol infrastructure**, not a platform.

---

# 1. Core Concepts

GreyThing separates four concerns:

| Layer | Responsibility |
|------|---------------|
| Identity | Who a user is |
| Storage | Where data lives |
| Access | Who can read data |
| Services | Applications interacting with data |

Applications are **protocol clients**.

---

# 2. Identity

GreyThing uses **Decentralized Identifiers (DID)**.

Initial implementation uses the `did:web` method.

Example identity:
did:web:did.greything.com:u:alice

The DID resolves to a **DID Document**:
https://did.greything.com/u/alice/did.json


The DID Document contains:

- public verification keys
- authentication methods
- service endpoints

Identity continuity is anchored in **cryptographic root keys** rather than hosting providers.

---

# 3. Storage Model

GreyThing stores data as **content-addressed objects**.

Objects are identified by:
sha256-{hex}


Storage endpoints are referenced in the DID Document.

Example:
service:
type: SolidPod
endpoint: https://storage.example.com/gt/v1/did:web:example.com:u:alice


Storage endpoints may be operated by:

- individuals
- hosting providers
- organizations
- websites

Objects may include:

- blobs
- encrypted attachments
- grants
- application data

---

# 4. Capability Grants

GreyThing uses **capability-based access control**.

Permissions are represented as **signed grants**.

Example grant:

```json
{
  "type": "gt.grant.v1",
  "issuer": "did:web:did.greything.com:u:alice",
  "subject": "did:web:did.greything.com:u:bob",
  "resource": {
    "kind": "blob",
    "hash": "sha256-abcd..."
  },
  "perm": ["read"],
  "notBefore": "2026-03-03T00:00:00Z",
  "expiresAt": "2026-03-10T00:00:00Z",
  "nonce": "random-base64url",
  "sig": {
    "alg": "Ed25519",
    "kid": "did:web:did.greything.com:u:alice#key-1",
    "value": "base64url-encoded-signature"
  }
}
```

A grant authorizes a subject to access a resource.

Grants are:

* cryptographically signed
* independently verifiable
* portable across services

Unlike traditional ACL systems, permissions travel with the request.

# 5. Blob Access

Data objects are stored as blobs.

Example access request:
```
GET /gt/v1/{did}/blobs/sha256/{hex}
X-GT-DID: did:web:did.greything.com:u:bob
X-GT-Timestamp: 2026-03-03T12:00:00Z
X-GT-Signature: {base64url-signature}
X-GT-Grant: sha256-{grant-hex}
```
Server verifies:

* grant signature
* subject identity
* resource hash
* expiration time

If validation succeeds, the blob is returned.

# 6. Messaging (Reference Application)

GreyThing includes a reference messaging application.

Messaging demonstrates the protocol architecture.

Message flow:

* message encrypted client-side
* attachments encrypted with symmetric key
* encrypted blob uploaded to storage
* capability grant created for recipient
* message references blob and grant

Recipient:
* decrypts message
* retrieves blob using grant
* decrypts attachment

Messaging is a demonstration application, not core protocol infrastructure.

# 7. Service Interaction

Applications interact with GreyThing as protocol clients.

Services may include:
* messaging applications
* social feeds
* publishing systems
* AI agents
* marketplaces

Services retrieve user-authorized data rather than owning it.

# 8. AI Agents

GreyThing treats AI agents as external protocol clients.

Agents may:

* read authorized user content
* generate recommendations
* curate feeds

Agents access data using capability grants.
Agents never obtain unrestricted access to storage.

# 9. Storage Migration

Because storage is independent from identity:
1) user copies data to new storage provider
2) DID document is updated
3) new storage endpoint becomes authoritative

Identity remains unchanged.

# 10. Security Model

GreyThing uses established cryptographic primitives:

* Ed25519 signatures
* X25519 key exchange
* AES-GCM encryption

Private keys are generated and used client-side only.
Servers never receive usable private keys.

Security is based on:
* signature verification
* content-addressed storage
* capability-based access control

# 11. Durable Identity (Rotation, Revocation, Recovery)

Long-term portability requires that identities survive device loss and key compromise.
GreyThing uses a layered lifecycle model.

## Device Key Rotation and Revocation

Daily actions are performed using **device keys** delegated from the root identity key.

- Device keys can be rotated regularly.
- If a device is lost or compromised, the root key updates the DID document to **revoke** the device key.
- Clients resolving the DID MUST reject signatures from revoked keys after the revocation update.

## Root Key Recovery (Optional Passphrase Backup)

Users MAY create an encrypted backup of the root key protected by a passphrase.

- The backup is encrypted client-side.
- The backup is stored in user-owned storage.
- The passphrase is never sent to servers.

This enables recovery when a device is lost but the user still knows the passphrase.

## Guardian DIDs Recovery (Future Work)

Future versions MAY support **guardian-based recovery**.

A user MAY declare a set of **Guardian DIDs** and a threshold rule (e.g. 2-of-3) in the DID document or a linked recovery policy object.

Recovery flow (high level):
1. User requests recovery and proposes a new root public key.
2. Guardians issue signed approvals referencing the proposed new key.
3. When threshold is met, the identity publishes an updated DID document with the new root key.

This enables social recovery without centralized identity providers and without relying on a blockchain.

# 12. Design Principles

- **Portable identity** — anchored in cryptographic keys, not domains
- **Durable identity** — key rotation, revocation and recovery ensure identities survive device loss
- **User-owned storage** — migratable across providers
- **Capability-based access** — signed grants authorize access to specific resources
- **Protocol-first architecture** — open specifications designed for reuse across applications
- **Services as consumers** — services and agents retrieve user-authorized data rather than owning it

GreyThing provides protocol infrastructure rather than platforms.