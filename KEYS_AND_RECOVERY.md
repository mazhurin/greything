# Keys and Recovery — GreyThing

This document defines how **cryptographic keys** are generated, used, stored, and recovered in GreyThing.

The goal is to provide:

* strong security guarantees
* user sovereignty
* realistic recovery paths

GreyThing explicitly avoids custodial key management.

---

## 1. Design Principles

1. **Users own their keys** — GreyThing never has custody
2. **Client-side generation and signing only**
3. **Recovery is opt-in and explicit**
4. **Multiple independent recovery paths**
5. **No single party can take over an identity**

---

## 2. Key Types

GreyThing uses a multi-tier key architecture.

### 2.1 Root Identity Key

* Algorithm: Ed25519
* Purpose:

  * Sign DID Documents
  * Approve key rotation
  * Delegate device keys

Properties:

* Generated client-side
* Rarely used
* Highest security level

The root private key is never stored in plaintext outside the client.

---

### 2.2 Device / Session Keys

* Algorithm: Ed25519
* Purpose:

  * Sign posts, likes, comments
  * Daily user actions

Properties:

* Short-lived
* Device-bound
* Delegated from root key
* Replaceable

Device keys are revoked by updating the DID Document or delegation metadata.

---

### 2.3 Encryption Keys (X25519)

* Algorithm: X25519
* Purpose:

  * Key agreement for E2EE private messages
  * Derive shared secrets (HKDF-SHA256 + ChaCha20-Poly1305)

Properties:

* Device-bound
* Listed in DID Document under `keyAgreement`
* Replaceable — add/revoke via DID Document updates

---

## 3. Recovery

### 3.1 Design

Recovery is **opt-in**. Users choose a passphrase during registration (or later via `gt-recovery setup`). The root private key is encrypted and stored as a public blob in the user's storage pod. Anyone can fetch the ciphertext; only the passphrase holder can decrypt.

### 3.2 Encryption Scheme

```
passphrase → Argon2id(t=3, m=64MB, p=4, salt=rand(16)) → 32-byte key
key + rand(12) nonce → ChaCha20-Poly1305 → encrypt(Ed25519 privkey, 64 bytes)
```

### 3.3 Encrypted Key Blob

The blob is self-describing JSON stored as a content-addressed blob:

```json
{
  "type": "EncryptedRootKeyV1",
  "alg": "argon2id+chacha20poly1305",
  "publicKeyMultibase": "z6Mk...",
  "kdf": { "alg": "argon2id", "time": 3, "memory": 65536, "threads": 4, "saltB64": "..." },
  "nonceB64": "...",
  "ciphertextB64": "...",
  "hint": "childhood street + first pet",
  "createdAt": "2026-02-23T10:00:00Z"
}
```

* `publicKeyMultibase` — lets the recovery tool verify decryption succeeded locally
* `hint` — optional, public passphrase hint (omitted if empty)

The blob hash is pointed to by the `recovery-key` head in the user's storage pod.

### 3.4 DID Document: recoveryPolicy

When recovery is configured, the DID Document includes:

```json
{
  "recoveryPolicy": {
    "type": "PassphraseEncryptedKey",
    "storageHead": "recovery-key",
    "setAt": "2026-02-23T10:00:00Z"
  }
}
```

**Protected field**: device keys cannot add, remove, or modify `recoveryPolicy`. Only the root key can change it. This is enforced server-side by the DIDS server.

### 3.5 Recovery Flow

1. Fetch DID Document → read `recoveryPolicy.storageHead`
2. GET the head (e.g. `recovery-key`) → get blob hash
3. GET the blob (public, no auth required)
4. Display hint (if present)
5. Prompt for passphrase
6. Derive key with Argon2id, decrypt with ChaCha20-Poly1305
7. Verify decrypted public key matches `publicKeyMultibase`
8. Save recovered root key to keys directory

### 3.6 CLI Tools

**Set up or rotate recovery passphrase** (requires root key):

```bash
go run ./cmd/gt-recovery setup \
  --key .greything/keys/{id}-root.json \
  --did did:web:did.greything.com:u:{id}
```

**Recover root key from passphrase**:

```bash
go run ./cmd/gt-recovery recover \
  --did did:web:did.greything.com:u:{id} \
  --keys-dir .greything/keys
```

### 3.7 Passphrase Hint

The hint is stored in plaintext inside the encrypted key blob. It is **public** — anyone who fetches the blob can read it.

Good hints describe the *pattern*, not the *answer*:
* "childhood street + first pet"
* "favorite book title backwards"

Bad hints reveal the passphrase:
* "fluffy123"
* "the answer is blue"

---

## 4. Key Storage

All private keys are stored locally in `.greything/keys/` as JSON files with mode `0600`.

| File | Type | Purpose |
|------|------|---------|
| `{id}-root.json` | Ed25519 | Root identity key |
| `{id}-device-1.json` | Ed25519 | Device signing key |
| `{id}-x25519-1.json` | X25519 | Encryption key |

Key file format:

```json
{
  "kty": "Ed25519",
  "kid": "root",
  "createdAt": "2026-02-23T10:00:00Z",
  "publicKeyMultibase": "z6Mk...",
  "privateKeyB64Url": "..."
}
```

---

## 5. Key Lifecycle

1. **Generation** — `gt-register` creates root + device + x25519 keys
2. **Device keys** — add/revoke with `gt-device-key add|revoke`
3. **Root key rotation** — update DID Document with new root key (signed by old root key)
4. **Recovery** — `gt-recovery setup` encrypts root key with passphrase; `gt-recovery recover` restores it
