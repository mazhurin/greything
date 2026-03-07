# GreyThing Capability Grants Specification

Version: draft-v1
Status: experimental

---

## 1. Overview

Capability grants are signed JSON objects that authorize a **subject** (identified by DID) to access a specific **resource** owned by the **issuer**.

Grants are:
- **Self-authenticating** — verifiable by anyone with access to the issuer's DID Document
- **Content-addressed** — identified by the SHA-256 hash of their canonical form
- **Portable** — can be transmitted alongside requests or stored independently
- **Time-bounded** — include optional validity windows

Unlike ACL-based access control (where permissions are attached to resources), capability grants travel with the request. The holder of a valid grant can present it to any storage endpoint to gain access.

---

## 2. Grant Object

```json
{
  "type": "gt.grant.v1",
  "issuer": "did:web:did.greything.com:u:alice",
  "subject": "did:web:did.greything.com:u:bob",
  "resource": {
    "kind": "blob",
    "hash": "sha256-7c9f1e2b..."
  },
  "perm": ["read"],
  "notBefore": "2026-03-01T00:00:00Z",
  "expiresAt": "2026-03-31T00:00:00Z",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ",
  "sig": {
    "alg": "Ed25519",
    "kid": "did:web:did.greything.com:u:alice#device-1",
    "value": "base64url-encoded-signature"
  }
}
```

### 2.1 Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"gt.grant.v1"` |
| `issuer` | string | Yes | DID of the grant creator (resource owner) |
| `subject` | string | Yes | DID of the authorized party |
| `resource` | object | Yes | Resource being granted access to |
| `resource.kind` | string | Yes | Resource type. Currently `"blob"` |
| `resource.hash` | string | Yes | Content hash of the resource (`sha256-{hex}`) |
| `perm` | string[] | Yes | Permissions granted. Currently `["read"]` |
| `notBefore` | string | No | RFC 3339 timestamp. Grant is not valid before this time |
| `expiresAt` | string | No | RFC 3339 timestamp. Grant is not valid after this time |
| `nonce` | string | Yes | Random value to ensure unique hashes for identical grants |
| `sig` | object | Yes | Cryptographic signature |

### 2.2 Signature Object

| Field | Type | Description |
|-------|------|-------------|
| `sig.alg` | string | Signature algorithm. Must be `"Ed25519"` |
| `sig.kid` | string | Key identifier (DID URL fragment, e.g. `did:web:...#device-1`) |
| `sig.value` | string | Base64url-encoded Ed25519 signature (no padding) |

---

## 3. Canonicalization

### 3.1 Signature Input

The signature is computed over the **canonical JSON** of the grant object **with the `sig` field removed**.

Canonical JSON rules:
- Object keys sorted lexicographically
- No whitespace between tokens
- Standard JSON encoding for values
- UTF-8 encoding

Example: given the grant object above, remove the `sig` field and produce:

```
{"expiresAt":"2026-03-31T00:00:00Z","issuer":"did:web:did.greything.com:u:alice","nonce":"dGhpcyBpcyBhIHJhbmRvbSBub25jZQ","notBefore":"2026-03-01T00:00:00Z","perm":["read"],"resource":{"hash":"sha256-7c9f1e2b...","kind":"blob"},"subject":"did:web:did.greything.com:u:bob","type":"gt.grant.v1"}
```

The signature is `Ed25519(privateKey, canonicalBytes)`, encoded as base64url without padding.

### 3.2 Grant Hash

The grant hash is computed over the **canonical JSON of the full grant including the `sig` field**:

```
sha256-{hex of sha256(canonicalJSON(fullGrant))}
```

This means different signatures produce different hashes, making grants truly content-addressed.

---

## 4. Grant Storage

Grants are stored at the issuer's storage endpoint:

```
{did}/grants/{hex}
```

Where `{hex}` is the 64-character hex portion of the grant hash (without the `sha256-` prefix).

---

## 5. HTTP API

### 5.1 Create Grant

```
POST /gt/v1/{did}/grants
```

- **Authentication**: Required. Caller must own the namespace.
- **Body**: Complete grant JSON including signature.
- **Validation**:
  1. Caller's authenticated DID must match `{did}` in the URL
  2. `grant.issuer` must match `{did}` (server does not trust the body issuer blindly)
  3. Grant signature must verify against the issuer's DID Document keys
  4. `type` must be `"gt.grant.v1"`
  5. Required fields must be present
- **Response**: `201 Created`

```json
{
  "grantHash": "sha256-abc123..."
}
```

### 5.2 Read Grant

```
GET /gt/v1/{did}/grants/{hex}
```

- **Authentication**: Not required. Grants are self-authenticating — anyone can read and verify them.
- **Response**: The stored grant JSON.

---

## 6. Grant-Based Blob Access

When a blob has a non-public ACL and the caller is not the owner or listed in the ACL, the storage server checks for a capability grant.

### 6.1 Request

```
GET /gt/v1/{did}/blobs/sha256/{hex}
X-GT-DID: did:web:did.greything.com:u:bob
X-GT-Timestamp: 2026-03-05T12:00:00Z
X-GT-Signature: {base64url}
X-GT-Grant: sha256-{grantHex}
```

The `X-GT-Grant` header contains the full grant hash (with `sha256-` prefix).

### 6.2 Server Validation

When the `X-GT-Grant` header is present, the server:

1. Loads the grant from storage by hash
2. Verifies the grant signature against the issuer's DID Document
3. Checks `grant.issuer == {did}` (only the blob owner can issue grants for their blobs)
4. Checks `grant.subject == caller DID` (the grant must be for this caller)
5. Checks `grant.resource.kind == "blob"` and `grant.resource.hash == "sha256-{hex}"` (resource match)
6. Checks `"read" in grant.perm` (permission match)
7. Checks `now >= grant.notBefore` (if present)
8. Checks `now <= grant.expiresAt` (if present)

If all checks pass, the blob is served. Otherwise, `404 Not Found` is returned (consistent with privacy behavior — no information leakage about whether the blob exists).

### 6.3 Access Control Priority

The server evaluates access in this order:

1. No metadata exists → **public** (backward compatible)
2. ACL contains `*` → **public**
3. Caller is namespace owner → **allowed**
4. Caller DID is in ACL → **allowed**
5. Valid `X-GT-Grant` header → **allowed**
6. Otherwise → **denied** (404)

---

## 7. Use Case: Encrypted Attachments

The primary use case for grants is sharing encrypted file attachments in private messages.

### 7.1 Sender Flow

1. Generate random AES-256-GCM key `K`
2. Encrypt file with `K` → encrypted blob
3. Upload encrypted blob to own storage (with private ACL `[]`)
4. Create grant for recipient over the blob hash
5. Sign grant with Ed25519 device key
6. Upload grant to own storage
7. Encrypt `K` for recipient using X25519 ECDH
8. Include `blobHash`, `grantHash`, and `encryptedKey` in the PM attachments

### 7.2 Recipient Flow

1. Decrypt PM → extract attachment metadata
2. Decrypt the AES key using own X25519 private key
3. Fetch blob from sender's storage with `X-GT-Grant` header
4. Decrypt blob with recovered AES key

### 7.3 Attachment Metadata in PM

```json
{
  "blobHash": "sha256-...",
  "grantHash": "sha256-...",
  "encryptedKey": {
    "v": 1,
    "epk": "base64url-ephemeral-public-key",
    "iv": "base64url-12-byte-iv",
    "ct": "base64url-encrypted-aes-key"
  },
  "filename": "photo.jpg",
  "mime": "image/jpeg",
  "size": 123456
}
```

### 7.4 Encrypted Key Derivation

The `encryptedKey` object wraps the AES-256-GCM file key for the recipient:

1. Generate ephemeral X25519 keypair
2. ECDH: `sharedSecret = X25519(ephemeralPriv, recipientPub)`
3. HKDF-SHA256: `wrapKey = HKDF(sharedSecret, salt=empty, info="greything.att.v1")`
4. AES-256-GCM encrypt: `ct = Encrypt(wrapKey, iv, fileKey)`

### 7.5 Encrypted Blob Format

```
GTATT1 || IV (12 bytes) || ciphertext + GCM tag
```

- `GTATT1` — 6-byte ASCII magic header
- IV — 12-byte random initialization vector
- Remaining bytes — AES-256-GCM ciphertext with appended authentication tag

---

## 8. Security Properties

- **Least privilege**: Grants authorize access to specific resources, not entire storage namespaces.
- **Time-bounded**: Grants can expire. Expired grants are rejected.
- **Non-transferable**: Grants are bound to a specific subject DID. Another user cannot reuse someone else's grant.
- **Issuer authority**: Only the resource owner (blob namespace owner) can create valid grants. The server enforces `grant.issuer == route.did`.
- **Self-authenticating**: Grants carry their own proof of authorization. Any party can verify a grant by resolving the issuer's DID Document.
- **Privacy-preserving**: Failed grant validation returns `404`, not `403`, to avoid revealing blob existence.
- **Replay protection**: The `nonce` field ensures that identical logical grants produce different hashes, preventing hash collision attacks.

---

## 9. Limitations (v1)

- **Read-only**: Only `read` permission is supported. Write grants are not implemented.
- **Single resource**: Each grant authorizes access to exactly one blob. Wildcard grants are not supported.
- **No delegation**: Grants cannot be re-delegated. Only the resource owner can issue grants.
- **No revocation**: Grants cannot be explicitly revoked before expiry. Use short `expiresAt` windows to limit exposure.
- **No offline verification**: The server must resolve the issuer's DID Document to verify the grant signature. Offline grant verification is not supported.
