# gt-timestamp-v1 (GreyThing)

Status: Draft
Goal: verifiable "not-later-than" time attestations for GreyThing objects without changing blobs or signed metadata.

This spec defines a **timestamp attestation object** that any issuer (GreyThing or third-party) can publish.
It is designed to be:
- content-addressed (immutable)
- signed (verifiable)
- linkable to any GreyThing object (blob or metadata)
- optional / additive (does not require protocol migration)

---

## 1. Overview

GreyThing objects are content-addressed. A timestamp is an **external claim**:

> "This subject hash existed / was observed by the issuer no later than `observedAt`."

A timestamp does **not** prove authorship by itself.
Authorship comes from the signed metadata (e.g., blob meta with `sig`).
Timestamp adds a time bound.

Recommended chain:
- `timestamp → signed metadata hash → content blob hash`

---

## 2. Identifiers

### 2.1 Subject identifiers

A timestamp subject MUST be a content hash in GreyThing format:
- `sha256-<hex>` (64 hex characters)

This matches the hash format used in GreyThing Storage API.

### 2.2 Timestamp object ID

Timestamp attestations are stored as content-addressed objects:
- object ID = `sha256-` + hex(sha256(canonical_json(attestation_without_sig)))
- stored in issuer's storage namespace

Example:
```
https://storage.greything.com/blob/{issuerUserId}/sha256-{timestampHash}
```

---

## 3. Timestamp Attestation Document

Content-Type: `application/json`

### 3.1 Schema

```json
{
  "v": 1,
  "type": "gt.timestamp",

  "subject": "sha256-abc123...",
  "subjectType": "meta",

  "issuer": "did:web:did.greything.com:u:timestamper",
  "observedAt": "2026-02-06T13:11:02Z",

  "method": "append-log",
  "evidence": {
    "logId": "sha256-def456...",
    "entry": 12345,
    "note": "optional human-readable"
  },

  "sig": "base64url-ed25519-signature"
}
```

### 3.2 Required fields

| Field | Description |
|-------|-------------|
| `v` | MUST be `1` |
| `type` | MUST be `"gt.timestamp"` |
| `subject` | Hash of the object being timestamped (`sha256-...`) |
| `subjectType` | Type of subject: `"meta"`, `"blob"`, or `"manifest"` |
| `issuer` | DID of the timestamp issuer |
| `observedAt` | RFC3339 UTC timestamp when subject was observed |
| `method` | Anchoring method (see Section 6) |
| `sig` | Ed25519 signature (base64url) |

### 3.3 Optional fields

| Field | Description |
|-------|-------------|
| `evidence` | Issuer-specific anchoring references |
| `evidence.logId` | Hash of the append-only log |
| `evidence.entry` | Entry number in the log |
| `evidence.tx` | Blockchain transaction reference |
| `evidence.note` | Human-readable note |

---

## 4. Canonicalization & Signing

### 4.1 Canonicalization

For signing, the document MUST be canonicalized as:
- UTF-8 encoding
- JSON keys sorted lexicographically
- No insignificant whitespace
- Exclude `sig` field from signed payload

### 4.2 Signature

- Algorithm: Ed25519
- Signature covers canonical JSON of all fields except `sig`
- `sig` is base64url encoding of the 64-byte Ed25519 signature
- Issuer's public key resolved from DID Document

---

## 5. Verification Procedure

Given a timestamp attestation T:

1. Check `T.v == 1` and `T.type == "gt.timestamp"`
2. Validate `observedAt` is valid RFC3339 UTC
3. Resolve `T.issuer` DID document and get public key
4. Verify signature over canonicalized T (excluding `sig`)
5. Validate `subjectType` matches expected subject format

If steps 1–5 pass, the timestamp is cryptographically valid as:

> "Issuer DID asserts it observed subject no later than observedAt."

Optional: If `evidence` present, verify issuer-specific evidence (log inclusion, tx inclusion).

---

## 6. Issuance Methods

### 6.1 Append-only log (recommended)

Issuer maintains an append-only log and publishes entries referencing subjects.

```json
{
  "method": "append-log",
  "evidence": {
    "logId": "sha256-...",
    "entry": 12345
  }
}
```

### 6.2 Receipt / notarization

Issuer returns a signed receipt as the timestamp.

```json
{
  "method": "receipt",
  "evidence": {
    "note": "Request ID: abc123"
  }
}
```

### 6.3 Blockchain anchoring

Issuer anchors a Merkle root or hash on-chain.

```json
{
  "method": "blockchain",
  "evidence": {
    "tx": "ethereum:0xabc123..."
  }
}
```

---

## 7. Multiple Timestamps & Trust

GreyThing supports multiple independent issuers.

Consumers MAY apply local trust policies:
- Allowlist of trusted issuers
- Threshold (e.g., 2-of-5 issuers)
- Preference ordering (e.g., "university log" > "commercial")

This spec does not define trust ranking.

---

## 8. Relationship to Authorship

Typical proof chain for "Alice authored content by time T":

**Step 1: Verify signed metadata M**
- `M.owner == did:alice`
- Signature by did:alice is valid
- `M.hash == sha256-{blobHash}`

**Step 2: Verify timestamp T**
- `T.subject == sha256-{metaHash}`
- Signature by `T.issuer` is valid
- `T.observedAt <= desiredTime`

**Result:**
- Alice cryptographically bound herself to the content
- External issuer attested that binding existed by `observedAt`

---

## 9. Privacy Notes

- Timestamping metadata hashes can leak correlation if metadata is public
- Private content SHOULD timestamp the metadata hash (not the blob)
- Timestamping encrypted metadata still allows existence proof

---

## 10. Storage API

Timestamps are stored as regular blobs in the issuer's namespace:

```
PUT /blob/{issuerUserId}/{timestampHash}:meta
PUT /blob/{issuerUserId}/{timestampHash}

GET /blob/{issuerUserId}/{timestampHash}
```

The timestamp blob contains the JSON attestation document.
The meta contains standard fields (`owner`, `acl`, `contentType`, etc.) plus `sig`.

### Discovery

To find timestamps for an object:
- Issuer publishes a manifest of timestamped subjects
- Or: client queries known timestamp issuers directly
- Or: index service aggregates timestamps (future)

---

## 11. Example

**Request timestamp for metadata:**

Metadata hash: `sha256-abc123def456...`

**Timestamp attestation:**

```json
{
  "v": 1,
  "type": "gt.timestamp",
  "subject": "sha256-abc123def456...",
  "subjectType": "meta",
  "issuer": "did:web:did.greything.com:u:timestamper",
  "observedAt": "2026-02-06T13:11:02Z",
  "method": "receipt",
  "sig": "xYz789..."
}
```

**Verification:**
1. Resolve `did:web:did.greything.com:u:timestamper` → get public key
2. Canonicalize JSON (without `sig`): `{"issuer":"did:web:...","method":"receipt",...}`
3. Verify Ed25519 signature
4. Confirm `observedAt` is acceptable timestamp
