# GreyThing Discovery Specification

Version: draft-v1
Status: experimental

---

## 1. Overview

GreyThing discovery enables users and services to find identities by human-meaningful attributes (name, city, keywords, contact hashes) rather than by DID alone.

Discovery is based on **claims** — self-asserted key-value attributes stored in user-owned storage and indexed by discovery providers.

DIDs are stable cryptographic identifiers, not designed for human lookup. Discovery bridges the gap between human-meaningful attributes and cryptographic identities.

---

## 2. Design Principles

- **DID is not a discovery identifier** — DIDs are stable cryptographic identifiers, not meant for human search.
- **Claims are user-owned** — claims live in user-owned storage, not in registries.
- **Discovery is non-authoritative** — indexers cache and rank claims but are not the source of truth.
- **Privacy by default** — sensitive attributes (phone, email) are stored as hashes and matched only by exact lookup.

---

## 3. Claims Model

Claims are key-value pairs published by the user. Each claim has a string key and a string value.

### 3.1 Example Claims

| Key | Value | Description |
|-----|-------|-------------|
| `name` | `Alice` | Display name |
| `family_name` | `Smith` | Family name |
| `city` | `Amsterdam` | City |
| `keywords` | `developer, crypto` | Free-form tags |
| `phone_hash` | `sha256-7c9f1e2b...` | SHA-256 hash of phone number |
| `email_hash` | `sha256-a3b8c1d4...` | SHA-256 hash of email address |

### 3.2 Privacy-Sensitive Claims

Phone numbers and email addresses are stored as SHA-256 hashes:

```
sha256-{hex of SHA-256(plaintext)}
```

Hash-based claims:
- Are matched by exact lookup only
- Are excluded from full-text search
- Convention: keys ending in `_hash` are treated as hash-based claims

---

## 4. Claims Manifest

Claims are published as a **claims manifest** — a JSON object stored as a content-addressed blob in user-owned storage.

```json
{
  "version": 1,
  "did": "did:web:did.greything.com:u:alice",
  "claims": {
    "name": "Alice",
    "family_name": "Smith",
    "city": "Amsterdam",
    "phone_hash": "sha256-7c9f1e2b..."
  },
  "createdAt": "2026-03-05T12:00:00Z"
}
```

### 4.1 Manifest Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | number | Yes | Must be `1` |
| `did` | string | Yes | The subject DID |
| `claims` | object | Yes | Key-value pairs (string → string) |
| `createdAt` | string | Yes | RFC 3339 timestamp |

### 4.2 Storage

The manifest is stored as a blob in the user's storage. The `claims` head points to the current manifest:

```
HEAD claims → sha256-{manifestBlobHash}
```

Updated via CAS (compare-and-swap) when claims change.

---

## 5. Indexing

Discovery providers (indexers) build search indexes from claims manifests.

### 5.1 Reindex Flow

1. User updates claims manifest in storage (blob + head)
2. User or storage triggers reindex: `POST /api/v1/did/{id}/reindex`
3. Indexer fetches `claims` head from storage
4. Indexer fetches manifest blob by hash
5. Indexer validates manifest DID matches the request
6. Indexer writes a local `claims-index.json` for the user

### 5.2 Claims Index

The indexer stores a local copy for search:

```json
{
  "did": "did:web:did.greything.com:u:alice",
  "claims": {
    "name": "Alice",
    "city": "Amsterdam"
  },
  "headHash": "sha256-...",
  "indexedAt": "2026-03-05T12:01:00Z"
}
```

### 5.3 Reindex Authentication

- Authenticated requests: caller must own the namespace (standard `X-GT-DID`/`X-GT-Timestamp`/`X-GT-Signature` headers)
- Internal requests: `X-GT-Internal: true` header bypasses authentication (for server-to-server calls on localhost)

---

## 6. Search API

### 6.1 Full-Text Search

```
GET /api/v1/search?q={query}
```

- Case-insensitive substring match across all claim values
- Claims with keys ending in `_hash` are excluded from full-text search
- Returns all matching identities

**Response:**

```json
[
  {
    "did": "did:web:did.greything.com:u:alice",
    "claims": {
      "name": "Alice",
      "city": "Amsterdam"
    }
  }
]
```

### 6.2 Exact Lookup

```
GET /api/v1/lookup?key={key}&value={value}
```

- Exact match on a specific claim key-value pair
- Used for hash-based discovery (phone, email)

**Example — find user by phone hash:**

```
GET /api/v1/lookup?key=phone_hash&value=sha256-7c9f1e2b...
```

**Response:** Same format as search.

---

## 7. Publishing Claims (CLI)

The `gt-claims` CLI tool provides an interactive interface:

1. Load Ed25519 signing key
2. Fetch current claims manifest from storage
3. Add, edit, or delete claims interactively
4. Auto-detect phone numbers and offer to store as `phone_hash`
5. Save: upload manifest blob to storage, update `claims` head via CAS
6. Reindex is triggered automatically after save

---

## 8. External DID Indexing

The indexer supports indexing DIDs from external domains (not just local users):

```
POST /api/v1/external-did/reindex
```

External claims are stored under a separate `ext/` directory and included in search results alongside local DIDs.

---

## 9. Security and Privacy

- **No global registry** — each indexer builds its own index from user-published claims
- **Hash-based privacy** — sensitive attributes are stored as SHA-256 hashes, preventing enumeration
- **User-controlled publication** — claims are published by the user, not extracted by the indexer
- **Cryptographic binding** — manifest DID must match the authenticated request DID
- **No phone-to-DID mapping on server** — the server stores only hashes, never plaintext phone numbers or emails

---

## 10. Limitations (v1)

- **No signed claims** — claims are self-asserted, not cryptographically signed individually
- **No third-party attestations** — no verifier model in v1 (planned for future versions)
- **No ranking** — search results are unordered
- **Linear scan** — indexer scans all claims files per query (sufficient for current scale)
- **No pagination** — search and lookup return all matching results
