# User Registration Flow (v1)

This document defines the user registration flow in GreyThing.
The goal is to allow self-sovereign user identities without requiring trusted third-party signing,
while keeping the process simple, web-native, and scalable.

---

## Design Principles

- Users own their cryptographic keys.
- Users generate their own identifiers.
- The system does not require a central authority to sign user identities.
- Registration must work without any always-on signing service.
- DID resolution must work via static HTTPS hosting.

---

## Actors

- **User Client**  
  A browser, mobile app, or CLI controlled by the user.

- **DID Hosting Domain**  
  A domain hosting DID Documents as static files (e.g. `did.greything.com`).

- **Registry Service (optional)**  
  A provisioning service that validates requests and writes files.
  The registry is NOT required for DID resolution.

---

## Identifier Types

### Canonical Identity (DID)

User identities are represented by opaque DIDs:

did:web:did.greything.com:u:<id>

Where `<id>` is a client-chosen opaque identifier.

### Human-Readable Name (Handle)

Users may optionally register a human-readable handle:

<name>@<domain>

Example:

alice@greything.com

Handles are aliases and are not part of the canonical identity.

---

## Registration Flow Overview

1. Client generates cryptographic keys.
2. Client generates an opaque user identifier.
3. Client proves possession of the private key.
4. Registry validates the proof.
5. DID Document is published as a static file.
6. Optional handle is mapped to the DID.

---

## Step-by-Step Flow

### Step 1: Key Generation (Client)

The client generates a cryptographic key pair locally.

- Algorithm: Ed25519
- Private key never leaves the client.

This key becomes the initial verification method for the user DID.

---

### Step 2: Generate Opaque User ID (Client)

The client generates a random opaque identifier:

- MUST be unique within the domain namespace.
- MUST NOT be derived from the public key.
- MAY be chosen for vanity purposes.

Example:

3x9f2k7m

Resulting DID:

did:web:did.greything.com:u:3x9f2k7m

---

### Step 3: Proof of Possession (Client)

The client proves control of the private key by signing a deterministic message.

Example message:

register:did:web:did.greything.com:u:3x9f2k7m

The client sends to the registry:

- user ID
- public key
- signature (proof)

---

### Step 4: Validation (Registry)

The registry performs the following checks:

- The user ID is syntactically valid.
- The user ID is not already registered.
- The signature verifies against the provided public key.
- Policy constraints are satisfied (rate limits, reserved IDs, etc.).

The registry does NOT sign anything.

---

### Step 5: DID Document Creation (Registry)

If validation succeeds, the registry writes a DID Document as a static file.

Path:

https://did.greything.com/u/<id>/did.json

Minimal DID Document example:

{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:did.greything.com:u:3x9f2k7m",
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.greything.com:u:3x9f2k7m",
      "publicKeyMultibase": "z6Mk..."
    }
  ],
  "assertionMethod": ["#key-1"]
}

Once written, the DID becomes globally resolvable.

---

### Step 6: Optional Handle Registration

If the user requests a handle:

alice@greything.com

The registry updates the handle mapping:

alice → did:web:did.greything.com:u:3x9f2k7m

Handle resolution is served via:

https://greything.com/.well-known/greything/resolve

---

## Failure Modes

- If the registry is offline, no new registrations occur, but existing DIDs continue to resolve.
- If handle registration fails, the DID remains valid and usable.
- If handle conflicts occur, the user may choose a different handle without changing the DID.

---

## Security Properties

- The registry never holds user private keys.
- The registry never signs user identities.
- DID ownership is proven cryptographically by key possession.
- DID resolution does not depend on the registry being online.
- Handle resolution does not affect identity validity.

---

## Summary

- Users generate their own keys and identifiers.
- DIDs are opaque, stable, and self-sovereign.
- Registration requires proof of key possession, not trusted signatures.
- DID Documents are static and always resolvable.
- Handles are optional, mutable, and domain-scoped.
