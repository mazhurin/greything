# GreyThing Storage Specification

Version: draft-v1
Status: experimental

---

## 1. Overview

GreyThing storage provides a user-owned, content-addressed object store with three primitives:

- **Blobs** — immutable, content-addressed binary objects
- **Heads** — mutable pointers to blobs, updated via compare-and-swap (CAS)
- **Inbox** — anonymous message drop box for receiving encrypted messages

All data is namespaced per DID. Users authenticate with Ed25519 signatures.

---

## 2. Base URL

Storage endpoints are declared in the user's DID Document:

```json
{
  "type": "SolidPod",
  "serviceEndpoint": "https://storage.greything.com/gt/v1/did:web:did.greything.com:u:alice"
}
```

All API paths are relative to:
```
/gt/v1/{did}
```

Where `{did}` is the full DID string (e.g. `did:web:did.greything.com:u:alice`).

---

## 3. Blobs

Blobs are immutable, content-addressed binary objects. A blob's identity is the SHA-256 hash of its contents.

### 3.1 Upload Blob

```
PUT /gt/v1/{did}/blobs/sha256/{hex}
```

- **Authentication**: Required. Caller must own the namespace (`auth.DID == route.did`).
- **Body**: Raw blob bytes.
- **Verification**: Server computes `sha256(body)` and verifies it matches `{hex}`.
- **Response**: `201 Created` on success.
- **Conflict**: `409` if blob already exists (content-addressed deduplication).

### 3.2 Read Blob

```
GET /gt/v1/{did}/blobs/sha256/{hex}
```

- **Authentication**: Optional. Required if blob has non-public ACL.
- **Access control**:
  1. No metadata → public (backward compatible)
  2. ACL contains `*` → public
  3. ACL contains caller's DID → allowed
  4. Caller is namespace owner → allowed
  5. Valid capability grant via `X-GT-Grant` header → allowed (see [grants-v1.md](grants-v1.md))
  6. Otherwise → `404 Not Found`
- **Response**: Raw blob bytes with `Content-Type: application/octet-stream`.
- **Caching**: `Cache-Control: public, max-age=31536000, immutable` (blobs are content-addressed and never change).

### 3.3 Delete Blob

```
DELETE /gt/v1/{did}/blobs/sha256/{hex}
```

- **Authentication**: Required. Caller must own the namespace.
- **Effect**: Deletes blob and associated metadata.
- **Response**: `204 No Content`.

### 3.4 Hash Format

All blob hashes use the format:
```
sha256-{64 lowercase hex characters}
```

Example:
```
sha256-7c9f1e2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
```

---

## 4. Blob Metadata

Metadata is stored separately from the blob and controls access.

### 4.1 Set Metadata

```
PUT /gt/v1/{did}/blobs/sha256/{hex}:meta
```

- **Authentication**: Required. Caller must own the namespace.
- **Prerequisite**: Blob must exist.
- **Body**:

```json
{
  "acl": ["*"],
  "contentType": "image/jpeg"
}
```

### 4.2 Read Metadata

```
GET /gt/v1/{did}/blobs/sha256/{hex}:meta
```

- **Authentication**: Required. Owner only.

### 4.3 ACL Values

| ACL | Meaning |
|-----|---------|
| `["*"]` | Public — anyone can read |
| `[]` | Private — owner only (or via capability grant) |
| `["did:web:..."]` | Specific DIDs allowed |

When no metadata exists, the blob is **public by default** (backward compatibility).

### 4.4 Metadata Object

```json
{
  "acl": ["did:web:did.greything.com:u:bob"],
  "contentType": "application/json",
  "createdAt": "2026-03-01T00:00:00Z",
  "updatedAt": "2026-03-02T00:00:00Z"
}
```

`createdAt` is set on first metadata write. `updatedAt` is set on subsequent updates.

---

## 5. Heads

Heads are mutable pointers to content-addressed blobs. They provide the single mutable primitive in an otherwise immutable storage system.

Heads are updated via **compare-and-swap (CAS)** to prevent race conditions.

### 5.1 Read Head

```
GET /gt/v1/{did}/heads/{name}
```

- **Authentication**: Not required. Heads are public.
- **Response**:

```json
{
  "head": "sha256-abcdef...",
  "updatedAt": "2026-03-01T12:00:00Z"
}
```

### 5.2 Update Head (CAS)

```
PUT /gt/v1/{did}/heads/{name}
```

- **Authentication**: Required. Caller must own the namespace.
- **Body**:

```json
{
  "expected": "sha256-oldvalue...",
  "head": "sha256-newvalue..."
}
```

- `expected`: Current value of the head. Empty string `""` for initial creation.
- `head`: New value to set.
- **Response**: `200 OK` with the new head value.
- **Conflict**: `409` if `expected` does not match the current value.

### 5.3 Common Heads

| Name | Purpose |
|------|---------|
| `claims` | Public profile claims manifest |
| `pm` | Private messages conversation manifest (encrypted) |

Head names are arbitrary strings. Applications define their own conventions.

---

## 6. Inbox

The inbox is an anonymous message drop box. Anyone can post encrypted messages to a user's inbox without authentication. Only the inbox owner can read and delete messages.

### 6.1 Post Message

```
POST /gt/v1/{did}/inbox
```

- **Authentication**: Not required (anonymous delivery).
- **Body**: JSON envelope (max 64 KB):

```json
{
  "type": "InboxCiphertextV1",
  "alg": "X25519+HKDF+AES256GCM",
  "ephemeralPubB64": "...",
  "nonceB64": "...",
  "ciphertextB64": "..."
}
```

- **Limit**: Maximum 200 items per inbox.
- **Response**: `201 Created` with server-assigned ID:

```json
{
  "id": "20260301T120000Z-a1b2c3d4"
}
```

### 6.2 List Inbox

```
GET /gt/v1/{did}/inbox
```

- **Authentication**: Required. Owner only.
- **Response**:

```json
[
  { "id": "20260301T120000Z-a1b2c3d4", "size": 1234 },
  { "id": "20260301T120100Z-e5f6a7b8", "size": 567 }
]
```

### 6.3 Read Inbox Item

```
GET /gt/v1/{did}/inbox/{id}
```

- **Authentication**: Required. Owner only.

### 6.4 Delete Inbox Item

```
DELETE /gt/v1/{did}/inbox/{id}
```

- **Authentication**: Required. Owner only.
- **Response**: `204 No Content`.

---

## 7. Error Responses

All errors return JSON:

```json
{
  "error": "not_found",
  "message": "blob not found"
}
```

| Status | Error Code | Meaning |
|--------|-----------|---------|
| 400 | `bad_request` | Malformed request |
| 401 | `unauthorized` | Missing or invalid authentication |
| 403 | `forbidden` | Authenticated but not authorized |
| 404 | `not_found` | Resource not found (also used for access denied, to avoid information leakage) |
| 409 | `conflict` | CAS conflict (heads) or blob already exists |
| 409 | `inbox_full` | Inbox at capacity (200 items) |
| 413 | `too_large` | Inbox item exceeds 64 KB |
| 422 | `hash_mismatch` | Uploaded blob hash does not match URL |

---

## 8. Health Check

```
GET /gt/v1/health
```

Returns:
```json
{
  "status": "ok"
}
```

---

## 9. Storage Layout

On the filesystem adapter, data is stored as:

```
{basePath}/
  {did}/
    blobs/
      sha256/
        {hex}           ← blob data
        {hex}:meta      ← blob metadata (JSON)
    heads/
      {name}            ← head pointer (JSON)
    inbox/
      {id}              ← inbox item (JSON)
    grants/
      {hex}             ← capability grant (JSON)
```

---

## 10. Design Properties

- **Content-addressed**: Blobs are identified by hash. Same content = same address. Blobs are immutable.
- **Single mutable primitive**: Heads provide CAS-based mutability. All other state is derived from heads pointing to immutable blobs.
- **Portable**: Storage can be migrated by copying files and updating the DID Document service endpoint.
- **Provider-independent**: Any HTTP server implementing this API can serve as a storage endpoint.
- **Privacy-preserving**: Access denied returns `404` (not `403`) to avoid revealing whether a blob exists.
