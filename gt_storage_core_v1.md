# GTStorage Core v1

## 1. Purpose

GTStorage Core defines the minimal storage protocol for GreyThing.

It provides:
- Immutable content-addressed blobs
- A single mutable primitive (head)
- DID-authenticated mutations
- A foundation for append-only data structures

It does NOT define:
- Video delivery
- Hot/cold tiers
- Quotas or billing
- Streaming
- Application semantics (manifests, feeds, etc.)

Those belong to Provider Extensions built on top of Core.

---

## 2. Core Principles

1. Blobs are immutable.
2. Hash defines identity.
3. Head is the only mutable primitive.
4. All higher-level data structures are client-defined.
5. Backend adapters are dumb (byte storage only).
6. Providers are replaceable.

---

## 3. Namespace

All Core resources are under:

/gt/v1/

---

## 4. Immutable Blobs

Path:

/gt/v1/blobs/{algo}/{hash}

Example:

/gt/v1/blobs/sha256/abc123...

Rules:

- Blob identity is defined by {algo} and {hash}.
- Server MUST verify that hash(body) == {hash}.
- Blobs MUST be immutable.
- Overwriting existing blobs MUST NOT be allowed.
- Blobs MAY contain any content (JSON, binary, encrypted data).
- Core does not interpret blob content.

---

## 5. Mutable Heads (Universal Primitive)

Path:

/gt/v1/heads/{scope}/{id}/{name}

Examples:

/gt/v1/heads/did/{did}/didlog  
/gt/v1/heads/user/{did}/manifest  
/gt/v1/heads/user/{did}/inbox  

Head object:

{
  "head": "sha256:abcdef...",
  "updatedAt": "2026-02-18T12:00:00Z"
}

Only "head" is required.

Semantics:

- A head points to the current entry in an append-only structure.
- The structure itself lives entirely in immutable blobs.
- Head is the only mutable primitive in Core.

---

## 6. Head Update Semantics (CAS)

Head updates MUST use compare-and-swap (CAS).

Request:

PUT /gt/v1/heads/{scope}/{id}/{name}

Body:

{
  "expected": "sha256:oldHash",
  "head": "sha256:newHash"
}

Rules:

- If current head != expected → return 409 Conflict.
- If equal → update succeeds.
- Only the owner of {id} may update.
- Head updates MUST be atomic.

This guarantees safe concurrent updates.

---

## 7. Authentication

All mutating operations require DID authentication.

Required Headers:

X-GT-DID  
X-GT-Timestamp  
X-GT-Signature  

Signature payload:

{timestamp}|{method}|{path}|{bodyHash}

Requirements:

- Ed25519 signature.
- Timestamp skew ≤ 5 minutes.
- DID must resolve successfully.
- Verification method must be authorized by the DID Document.

Key hierarchy is defined by the DID, not by Core.

---

## 8. Authorization Model

### 8.1 Blobs

- Public blobs MAY be readable without authentication.
- Private blobs MUST require DID authentication.
- Unauthorized access MUST return 404 (not 403).

Mutation rules:

- Only the owner DID may create or delete a blob.
- Metadata updates (if supported) MUST be owner-only.

### 8.2 Heads

- Only owner of {id} may update a head.
- Read access MAY be public or restricted.
- DID history heads SHOULD be public for verification.

---

## 9. Required Endpoints

### 9.1 Blob Endpoints

PUT /gt/v1/blobs/{algo}/{hash}

- Verifies hash matches body.
- Rejects if blob already exists.
- Returns 201 Created.

GET /gt/v1/blobs/{algo}/{hash}

- Returns raw bytes.
- Enforces ACL.

DELETE /gt/v1/blobs/{algo}/{hash}

- Owner only.
- Returns 204 No Content.

### 9.2 Head Endpoints

GET /gt/v1/heads/{scope}/{id}/{name}

Returns:

{
  "head": "sha256:..."
}

Returns 404 if not found.

PUT /gt/v1/heads/{scope}/{id}/{name}

Body:

{
  "expected": "sha256:oldHash",
  "head": "sha256:newHash"
}

Returns:

- 200 OK on success
- 409 Conflict if head mismatch

---

## 10. Data Model Responsibility

GTStorage Core does NOT define:

- Linked list structure
- Pagination
- DID log format
- Manifest format
- Feed semantics

Clients define:

- LogEntry structure
- prev references
- Signatures inside blobs
- Traversal logic

Core guarantees:

- Immutable storage
- Atomic head movement

---

## 11. Consistency Model

GTStorage Core provides:

- Strong consistency for blob writes.
- Atomic CAS for head updates.
- Eventual consistency with external systems (e.g., DID hosts).

Canonical truth consists of:

- Immutable blob graph.
- Current head pointer.

External snapshots (e.g., did.json) are caches.

---

## 12. Migration Guarantees

Provider migration requires:

1. Copy all referenced blobs.
2. Copy all head objects.
3. Update service endpoint in DID.

No transformation required.

Delivery or derivative objects are outside Core.

---

## 13. Minimal Adapter Interface

type StorageAdapter interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error
    Delete(key string) error
    Exists(key string) (bool, error)
}

Keys correspond to:

blobs/{algo}/{hash}  
heads/{scope}/{id}/{name}  

Adapter MUST NOT interpret content.

---

## 14. Invariants

1. Blob hash defines identity.
2. Blob immutability is absolute.
3. Head is the only mutable primitive.
4. CAS protects concurrent updates.
5. DID authentication protects ownership.
6. Core never depends on delivery layers.
7. Core is provider-agnostic.

---

## 15. Fundamental Pattern

All higher-level structures use a single pattern:

append immutable blob  
→ CAS move head  

One primitive. Everywhere.
