# Keys and Recovery — GreyThing

This document defines how **cryptographic keys** are generated, used, stored, and recovered in GreyThing.

The goal is to provide:

* strong security guarantees
* user sovereignty
* realistic recovery paths
* Web2-level usability where possible

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

### 2.3 Encrypted Backup Key

* Encrypted copy of the root private key
* Stored in the user's Solid Pod
* Encrypted client-side only

Encryption requirements:

* Strong KDF (Argon2 or scrypt)
* Unique salt
* Configurable work factor

The Solid Pod never stores usable private keys.

---

## 3. Key Generation Flow

1. User registers on first device
2. Client generates root identity key locally
3. Public key is published in DID Document
4. Root private key remains client-side
5. Encrypted backup is created and stored in Solid Pod
6. Device key is generated and delegated

GreyThing infrastructure is not involved in key generation.

---

## 4. Signing Flow

1. User performs an action
2. Client signs payload with device key
3. Signed data is stored in Solid Pod
4. Verifiers:

   * Resolve DID
   * Validate delegation chain
   * Verify signature

This ensures content authenticity independent of storage provider.

---

## 5. Backup Password vs Recovery Phrase

GreyThing distinguishes between two concepts:

### 5.1 Backup Password

* Protects the encrypted backup stored in the Solid Pod
* Can be changed
* Does not generate keys
* Used for recovery on new devices

This password protects a **copy**, not the identity itself.

---

### 5.2 Recovery Phrase (Seed Phrase)

* Deterministically generates the root identity key
* High-entropy word sequence
* Optional but strongly recommended
* Shown once during setup

Properties:

* Cannot be changed
* Must be stored offline
* Never uploaded or stored in the pod

Compromise or loss of the recovery phrase has irreversible consequences.

---

## 6. Recovery Scenarios

### 6.1 New Device Recovery (Most Common)

Requirements:

* Access to Solid Pod
* Backup password

Flow:

1. User authenticates to Solid Pod
2. Client downloads encrypted backup
3. User enters backup password
4. Root key is decrypted client-side
5. New device key is generated and delegated

---

### 6.2 Device-to-Device Authorization

Requirements:

* At least one trusted device

Flow:

1. Existing device authorizes new device
2. Delegation is signed by root key
3. New device becomes active

Root key never leaves the trusted device.

---

### 6.3 Recovery via Recovery Phrase

Requirements:

* Recovery phrase

Flow:

1. User enters recovery phrase
2. Root key is deterministically reconstructed
3. DID Document is updated
4. New device keys are issued

This method works even if Solid Pod data is lost.

---

### 6.4 Social or Service-Assisted Recovery (Optional)

Requirements:

* Pre-configured trusted parties
* Multi-party approval (M-of-N)

Flow:

1. Recovery request initiated
2. Trusted parties co-sign key rotation
3. DID Document is updated

GreyThing may participate as one co-signer but never alone.

---

## 7. Key Rotation

Key rotation is supported at all levels:

* Device key rotation: routine
* Root key rotation: rare, explicit

Rotation requires:

* Existing root key
* Or recovery mechanisms

Rotation updates the DID Document accordingly.

---

## 8. Threat Model Summary

### 8.1 Pod Compromise

* Encrypted backups may be stolen
* Without backup password, keys remain safe

---

### 8.2 GreyThing Compromise

* DID Documents may be temporarily unavailable
* No keys or content are exposed

---

### 8.3 Device Loss

* Recoverable via backup or recovery phrase

---

## 9. Explicit Non-Goals

GreyThing intentionally does NOT:

* Recover identities without user participation
* Store plaintext private keys
* Provide password-based identity custody
* Hide key responsibility from users

---

## 10. Summary

GreyThing key management provides:

* Strong cryptographic identity ownership
* Practical recovery paths
* Minimal trust in infrastructure providers

User sovereignty is preserved even in failure scenarios.
