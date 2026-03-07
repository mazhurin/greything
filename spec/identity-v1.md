# GreyThing Identity Specification

Version: draft-v1
Status: experimental

---

## 1. Overview

GreyThing identity is based on **Decentralized Identifiers (DIDs)** as defined by the [W3C DID Core specification](https://www.w3.org/TR/did-core/).

The current implementation uses the `did:web` method. Identity continuity is anchored in cryptographic root keys rather than domain ownership.

---

## 2. DID Format

```
did:web:{domain}:u:{userId}
```

Example:
```
did:web:did.greything.com:u:alice
```

The `userId` is an opaque identifier assigned at registration time. It is not a username or handle.

---

## 3. DID Document Resolution

A `did:web` identifier resolves to a DID Document via HTTPS:

```
did:web:did.greything.com:u:alice
  → https://did.greything.com/u/alice/did.json
```

Domain-level DID:
```
did:web:did.greything.com
  → https://did.greything.com/.well-known/did.json
```

---

## 4. DID Document Structure

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:did.greything.com:u:alice",
  "verificationMethod": [
    {
      "id": "did:web:did.greything.com:u:alice#root",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.greything.com:u:alice",
      "publicKeyMultibase": "z..."
    },
    {
      "id": "did:web:did.greything.com:u:alice#device-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.greything.com:u:alice",
      "publicKeyMultibase": "z..."
    },
    {
      "id": "did:web:did.greything.com:u:alice#x25519-1",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:web:did.greything.com:u:alice",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication": ["did:web:did.greything.com:u:alice#root"],
  "assertionMethod": ["did:web:did.greything.com:u:alice#root"],
  "capabilityInvocation": ["did:web:did.greything.com:u:alice#root"],
  "capabilityDelegation": ["did:web:did.greything.com:u:alice#root"],
  "keyAgreement": ["did:web:did.greything.com:u:alice#x25519-1"],
  "service": [
    {
      "id": "did:web:did.greything.com:u:alice#pod",
      "type": "SolidPod",
      "serviceEndpoint": "https://storage.greything.com/gt/v1/did:web:did.greything.com:u:alice"
    }
  ]
}
```

---

## 5. Key Types

### 5.1 Root Key (Ed25519)

- **Purpose**: Signs DID Document updates. Highest-trust key.
- **Type**: `Ed25519VerificationKey2020`
- **Fragment**: `#root`
- **Usage**: Rarely used. Stored offline or in secure backup.

### 5.2 Device Keys (Ed25519)

- **Purpose**: Daily signing operations (posts, messages, grants, API authentication).
- **Type**: `Ed25519VerificationKey2020`
- **Fragment**: `#device-1`, `#device-2`, etc.
- **Usage**: One per device. Can be rotated without changing root key.

### 5.3 Encryption Keys (X25519)

- **Purpose**: Key agreement for end-to-end encrypted communication.
- **Type**: `X25519KeyAgreementKey2020`
- **Fragment**: `#x25519-1`, etc.
- **Referenced in**: `keyAgreement` array.

---

## 6. Key Encoding

All public keys use **multibase base58btc** encoding:

```
publicKeyMultibase: "z..."
```

The `z` prefix indicates base58btc (Bitcoin alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).

The raw value is the 32-byte public key.

---

## 7. Service Endpoints

Service endpoints in the DID Document declare where a user's data is stored.

| Type | Purpose |
|------|---------|
| `SolidPod` | Storage API endpoint (blobs, heads, inbox, grants) |
| `GreyThingProfile` | Public profile page URL |
| `GreyThingEventStream` | Event stream endpoint |

The `SolidPod` endpoint is the primary storage service. It points to the base URL for all storage API operations for this DID.

---

## 8. Identity File Format

Users authenticate using an **identity file** containing their keys:

```json
{
  "did": "did:web:did.greything.com:u:alice",
  "keys": {
    "root": {
      "kty": "Ed25519",
      "kid": "root",
      "publicKeyMultibase": "z...",
      "privateKeyB64Url": "..."
    },
    "device-1": {
      "kty": "Ed25519",
      "kid": "device-1",
      "publicKeyMultibase": "z...",
      "privateKeyB64Url": "..."
    },
    "x25519-1": {
      "kty": "X25519",
      "kid": "x25519-1",
      "publicKeyMultibase": "z...",
      "privateKeyB64Url": "..."
    }
  }
}
```

The `privateKeyB64Url` field contains the 64-byte Ed25519 private key (seed + public) or 32-byte X25519 private key, encoded as base64url without padding.

Identity files are stored **client-side only**. The server never receives private keys.

---

## 9. Request Authentication

API requests are authenticated using HTTP headers:

| Header | Value |
|--------|-------|
| `X-GT-DID` | Caller's DID |
| `X-GT-Timestamp` | Current time in RFC 3339 format |
| `X-GT-Signature` | Ed25519 signature (base64url, no padding) |

### Signature Payload

```
{timestamp}|{method}|{path}|{bodyHash}
```

Where:
- `timestamp` — value of `X-GT-Timestamp`
- `method` — HTTP method (`GET`, `PUT`, `POST`, `DELETE`)
- `path` — request path (e.g. `/gt/v1/did:web:did.greything.com:u:alice/blobs/sha256/abcd...`)
- `bodyHash` — `sha256-{hex}` of the request body (empty body hashes to `sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)

### Verification

The server resolves the caller's DID to obtain Ed25519 public keys, then verifies the signature against the payload.

Timestamps older than **5 minutes** are rejected.

---

## 10. Identity Migration

Because identity is anchored in cryptographic keys rather than domains:

1. User registers with a new hosting provider
2. New provider creates a DID Document with the same root key
3. Old DID Document is updated with `alsoKnownAs` pointing to the new DID
4. Data is migrated from old storage to new storage
5. New DID becomes authoritative

The root key provides continuity across migrations.

---

## 11. Discovery

Users publish **claims** — public profile attributes stored as content-addressed blobs:

```json
{
  "version": 1,
  "did": "did:web:did.greything.com:u:alice",
  "claims": {
    "name": "Alice",
    "city": "Berlin",
    "keywords": "developer, crypto"
  },
  "createdAt": "2026-03-01T00:00:00Z"
}
```

Claims are stored as blobs and referenced via the `claims` head. They are indexed for search by the DID registry.

Sensitive fields (email, phone) are stored as hashes only (`sha256-{hex}` of the normalized value) to enable lookup without exposing the raw value.
