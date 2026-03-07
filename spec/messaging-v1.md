# GreyThing Messaging Specification

Version: draft-v1
Status: experimental

---

## 1. Overview

GreyThing messaging provides **end-to-end encrypted private messages** between DID-identified users. Messages are encrypted client-side and delivered through anonymous inbox endpoints. The server never sees plaintext content or sender metadata.

Messaging is a **demonstration application** built on top of the identity, storage, and grants layers.

---

## 2. Architecture

```
Sender                          Server                         Recipient
  │                               │                               │
  ├─ sign message (Ed25519)       │                               │
  ├─ encrypt (X25519+AES-GCM)    │                               │
  ├─ POST /inbox ────────────────►│ store opaque ciphertext       │
  │                               │                               │
  │                               │◄──────────── GET /inbox ──────┤
  │                               │              (authenticated)  │
  │                               │────────────► ciphertext ─────►│
  │                               │                               ├─ decrypt
  │                               │                               ├─ verify signature
  │                               │                               │
```

The server sees only opaque ciphertext. It does not know who sent a message, only who it was delivered to.

---

## 3. Message Layers

Messages have two layers:

### 3.1 Inner Layer — Signed Message

A plaintext JSON object signed by the sender's Ed25519 key.

```json
{
  "type": "PrivateMessageV1",
  "id": "urn:gt:pm:20260305T120000Z",
  "from": "did:web:did.greything.com:u:alice",
  "to": "did:web:did.greything.com:u:bob",
  "createdAt": "2026-03-05T12:00:00Z",
  "text": "Hello Bob!",
  "attachments": [],
  "signature": {
    "kid": "did:web:did.greything.com:u:alice#device-1",
    "alg": "Ed25519",
    "sig": "base64url-encoded-signature"
  }
}
```

### 3.2 Outer Layer — Encrypted Envelope

The signed message is encrypted for the recipient and wrapped in an `InboxCiphertextV1` envelope.

```json
{
  "type": "InboxCiphertextV1",
  "alg": "X25519+HKDF+AES256GCM",
  "ephemeralPubB64": "base64url-ephemeral-x25519-public-key",
  "nonceB64": "base64url-12-byte-iv",
  "ciphertextB64": "base64url-encrypted-inner-message"
}
```

---

## 4. Inner Message Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"PrivateMessageV1"` |
| `id` | string | Yes | Unique message ID (format: `urn:gt:pm:{timestamp}`) |
| `from` | string | Yes | Sender DID |
| `to` | string | Yes | Recipient DID |
| `createdAt` | string | Yes | RFC 3339 timestamp |
| `text` | string | Yes | Message body (may be empty if only attachments) |
| `attachments` | array | No | File attachments (see section 8) |
| `signature` | object | Yes | Ed25519 signature over canonical form |

### 4.1 Signature Object

| Field | Type | Description |
|-------|------|-------------|
| `signature.kid` | string | Sender's key ID (DID URL fragment) |
| `signature.alg` | string | Must be `"Ed25519"` |
| `signature.sig` | string | Base64url-encoded signature (no padding) |

---

## 5. Canonical Form for Signing

The signature is computed over a deterministic string representation of the message:

```
type=PrivateMessageV1\n
id={id}\n
from={from}\n
to={to}\n
createdAt={createdAt}\n
text={text}\n
attachments={attachmentsHash}\n
```

Where:
- Each field is followed by a literal `\n` (newline character)
- `attachmentsHash` is:
  - Empty string if no attachments (`attachments=\n`)
  - SHA-256 hex of `canonicalJSON(attachments)` if attachments are present

### 5.1 Canonical JSON

Canonical JSON uses sorted keys and no whitespace:

```
[{"blobHash":"sha256-...","encryptedKey":{...},"filename":"photo.jpg","grantHash":"sha256-...","mime":"image/jpeg","size":123456}]
```

### 5.2 Backward Compatibility

Messages without attachments produce the same canonical form as before the attachments feature was added — `attachments=\n` hashes identically whether the field is absent or empty.

---

## 6. Encryption

### 6.1 Key Exchange

Messages are encrypted using X25519 ECDH with an ephemeral keypair:

1. Sender generates ephemeral X25519 keypair
2. ECDH: `sharedSecret = X25519(ephemeralPriv, recipientX25519Pub)`
3. HKDF-SHA256: `aesKey = HKDF(sharedSecret, salt=empty, info="greything.pm.v1")`
4. AES-256-GCM: `ciphertext = Encrypt(aesKey, nonce, plaintext)`

### 6.2 Recipient Key Resolution

The recipient's X25519 public key is obtained from their DID Document:

```json
{
  "id": "did:web:...#x25519-1",
  "type": "X25519KeyAgreementKey2020",
  "publicKeyMultibase": "z..."
}
```

Referenced in the `keyAgreement` array.

### 6.3 HKDF Parameters

| Parameter | Value |
|-----------|-------|
| Hash | SHA-256 |
| Salt | Empty (zero-length) |
| Info | `"greything.pm.v1"` (UTF-8 bytes) |
| Output length | 256 bits |

---

## 7. Message Delivery

### 7.1 Sending

1. Resolve recipient's DID Document
2. Extract recipient's X25519 public key from `keyAgreement`
3. Extract recipient's storage endpoint from `service` (type `SolidPod`)
4. Build inner message, sign with Ed25519
5. Encrypt inner message for recipient
6. POST envelope to recipient's inbox:

```
POST {recipientStorageEndpoint}/inbox
Content-Type: application/json

{ "type": "InboxCiphertextV1", ... }
```

The inbox endpoint accepts anonymous posts — no authentication required. This prevents the server from learning the sender's identity.

### 7.2 Receiving

1. List inbox items (authenticated):
   ```
   GET /gt/v1/{did}/inbox
   ```
2. For each item, fetch and decrypt:
   ```
   GET /gt/v1/{did}/inbox/{id}
   ```
3. Decrypt envelope using own X25519 private key
4. Verify sender signature by resolving sender's DID Document
5. Store decrypted message locally (as encrypted-for-self blob)
6. Delete inbox item:
   ```
   DELETE /gt/v1/{did}/inbox/{id}
   ```

---

## 8. Attachments

Attachments are encrypted files stored as blobs in the sender's storage, shared with the recipient via capability grants.

### 8.1 Attachment Object

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

| Field | Type | Description |
|-------|------|-------------|
| `blobHash` | string | Hash of the encrypted blob in sender's storage |
| `grantHash` | string | Hash of the capability grant authorizing read access |
| `encryptedKey` | object | AES key encrypted for the recipient |
| `filename` | string | Original filename |
| `mime` | string | MIME type |
| `size` | number | Original file size in bytes (before encryption) |

### 8.2 Sender Flow

1. Generate random AES-256-GCM key `K`
2. Generate random 12-byte IV
3. Encrypt file: `ciphertext = AES-GCM(K, IV, fileBytes)`
4. Build blob: `"GTATT1" || IV (12 bytes) || ciphertext+tag`
5. Upload encrypted blob to own storage
6. Set blob ACL to `[]` (private)
7. Create and sign capability grant for recipient (see [grants-v1.md](grants-v1.md))
8. Upload grant to own storage
9. Encrypt `K` for recipient (X25519 ECDH key wrapping)
10. Include attachment metadata in PM `attachments` array

### 8.3 Encrypted Blob Format

```
Offset  Length  Content
0       6       "GTATT1" (ASCII magic header)
6       12      IV (random initialization vector)
18      *       AES-256-GCM ciphertext + authentication tag
```

### 8.4 Key Wrapping

The AES file key is encrypted for the recipient:

1. Generate ephemeral X25519 keypair
2. ECDH: `sharedSecret = X25519(ephemeralPriv, recipientX25519Pub)`
3. HKDF-SHA256: `wrapKey = HKDF(sharedSecret, salt=empty, info="greything.att.v1")`
4. AES-256-GCM: `ct = Encrypt(wrapKey, iv, fileKey)`

Note: The HKDF info string for attachment keys (`greything.att.v1`) is different from the one used for message encryption (`greything.pm.v1`).

### 8.5 Recipient Flow

1. Extract `encryptedKey` from attachment metadata
2. ECDH with ephemeral public key: `sharedSecret = X25519(ownPriv, epk)`
3. HKDF: `wrapKey = HKDF(sharedSecret, salt=empty, info="greything.att.v1")`
4. Decrypt: `fileKey = Decrypt(wrapKey, iv, ct)`
5. Fetch blob from sender's storage with grant:
   ```
   GET /gt/v1/{senderDID}/blobs/sha256/{hex}
   X-GT-DID: {ownDID}
   X-GT-Timestamp: ...
   X-GT-Signature: ...
   X-GT-Grant: sha256-{grantHex}
   ```
6. Verify blob magic header `GTATT1`
7. Extract IV (bytes 6–17) and ciphertext (bytes 18+)
8. Decrypt: `plaintext = AES-GCM-Decrypt(fileKey, IV, ciphertext)`

---

## 9. Client-Side Storage

Messages are stored locally as encrypted-for-self blobs with a conversation manifest.

### 9.1 Message Blobs

Each message (sent or received) is encrypted for self using the same X25519 envelope scheme and stored as a blob with owner-only ACL.

### 9.2 Conversation Manifest

The manifest is a JSON object tracking all conversations:

```json
{
  "version": 1,
  "conversations": {
    "did:web:did.greything.com:u:bob": {
      "lastMessageAt": "2026-03-05T12:00:00Z",
      "messages": [
        {
          "hash": "sha256-...",
          "dir": "out",
          "ts": "2026-03-05T12:00:00Z",
          "text": "Hello Bob!",
          "attachments": [...]
        },
        {
          "hash": "sha256-...",
          "dir": "in",
          "ts": "2026-03-05T12:01:00Z",
          "text": "Hi Alice!",
          "verified": true
        }
      ]
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `hash` | Blob hash of the encrypted message copy |
| `dir` | `"out"` (sent) or `"in"` (received) |
| `ts` | Message timestamp |
| `text` | Message text (cached for display) |
| `verified` | Signature verification result (incoming only) |
| `attachments` | Attachment metadata (if present) |

### 9.3 Manifest Storage

The manifest is encrypted for self and stored as a blob. The `pm` head points to the current manifest:

```
HEAD pm → sha256-{manifestBlobHash}
```

Updated via CAS after each inbox processing or message send.

---

## 10. Signature Verification

Recipients verify sender signatures to ensure message authenticity:

1. Resolve sender's DID Document
2. Extract Ed25519 verification methods
3. Reconstruct canonical form from message fields
4. Verify Ed25519 signature against canonical bytes

If verification fails, the message is still stored but marked `verified: false`. The UI displays a warning.

---

## 11. Privacy Properties

- **No sender metadata**: The inbox POST is anonymous. The server does not know who sent a message.
- **No plaintext on server**: The server stores only opaque ciphertext.
- **No conversation metadata**: The server cannot determine who is talking to whom. It only sees that someone posted to a specific inbox.
- **Forward secrecy per message**: Each message uses an ephemeral X25519 keypair. Compromise of the ephemeral key does not affect other messages.
- **Sender authentication**: The inner Ed25519 signature proves the sender's identity to the recipient, while remaining invisible to the server.

---

## 12. Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Message signing | Ed25519 | 32-byte keys, 64-byte signatures |
| Key agreement | X25519 | 32-byte keys |
| Key derivation (messages) | HKDF-SHA256 | info: `"greything.pm.v1"` |
| Key derivation (attachments) | HKDF-SHA256 | info: `"greything.att.v1"` |
| Message encryption | AES-256-GCM | 12-byte IV, 256-bit key |
| Attachment encryption | AES-256-GCM | 12-byte IV, 256-bit key |
| Content addressing | SHA-256 | `sha256-{hex}` format |
| Key encoding | Base64url | No padding |
| Public key encoding | Multibase base58btc | `z` prefix |
