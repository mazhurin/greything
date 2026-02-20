# Identity, Handles, and Vanity IDs (v1)

This document defines how identity, human-readable names, and vanity identifiers work in GreyThing.
The design goal is to keep identities stable and verifiable while allowing people to share simple,
memorable identifiers without global namespace conflicts.

---

## Canonical Identity (DID)

Every subject in GreyThing (users, services, agents) is identified by a Decentralized Identifier (DID).

User identities use the `did:web` method and opaque identifiers that are not derived from usernames
or cryptographic keys.

The canonical user DID format is:

did:web:did.greything.com:u:<id>

The `<id>` component:

- MUST be opaque and treated as an identifier only
- MUST NOT encode or be derived from a public key
- SHOULD be generated client-side
- MAY be chosen for vanity purposes, subject to policy

A DID is stable, long-lived, and independent of names or handles.  
Key rotation MUST NOT require changing the DID.  
Changing human-readable names MUST NOT change the DID.

---

## DID Documents

Each DID resolves to a DID Document (`did.json`) via HTTPS.

DID Documents:

- contain public keys and service endpoints
- are served as static JSON files
- MUST be retrievable without calling any API

Example resolution:

did:web:did.greything.com:u:3x9f2k7m  
→ https://did.greything.com/u/3x9f2k7m/did.json

---

## Handles (DID Names)

Handles (also called DID names) are human-readable aliases that resolve to DIDs.

A handle has the form:

<name>@<domain>

Example:

alice@greything.com

Handles are NOT identities.  
Handles are mutable.  
Handles are scoped to a domain.  
Uniqueness is required only within the domain namespace.

At any given time, a handle MUST resolve to exactly one DID.

---

## Vanity IDs

Vanity IDs refer to human-chosen opaque DID identifiers (`<id>` values) selected for aesthetics or
memorability.

Vanity IDs:

- MAY be generated and selected by the client before registration
- MUST still be treated as opaque identifiers
- MUST NOT be interpreted as usernames
- MUST NOT carry semantic meaning

Registries MAY enforce policy constraints, including:

- allowed character sets
- minimum and maximum length
- reserved words
- rate limits, proof-of-work, or other abuse controls

Vanity IDs do not affect the cryptographic meaning or security of the DID.

---

## Handle Resolution

Handles are resolved to DIDs using simple HTTPS requests to the handle’s domain.

Canonical resolution endpoint:

GET https://<domain>/.well-known/greything/resolve?name=<name>

Example request:

GET https://greything.com/.well-known/greything/resolve?name=alice

Example response:

{
  "name": "alice@greything.com",
  "did": "did:web:did.greything.com:u:3x9f2k7m"
}

The resolution endpoint:

- MAY be static or dynamic
- MAY return unsigned responses in v1
- MUST NOT be required for DID resolution itself

Handle resolution is a convenience mechanism only.

---

## Handle Changes and Identity Migration

Handles may be changed, released, or reassigned according to domain policy.

Changing a handle MUST NOT change the DID.

Domains SHOULD consider cooldown periods, reserved names, and abuse prevention rules.

Migration across domains MUST be established via a signed migration claim created using the old
DID’s keys.

HTTP redirects MAY be used for compatibility and UX, but redirects alone are NOT sufficient proof
of identity migration.

---

## Security and Anti-Abuse Considerations

Domains MAY reserve special handles such as `admin`, `support`, or system names.

Domains SHOULD apply rate limits to handle registration and vanity ID selection.

Domains MAY require proof-of-work or micropayments for high-demand names.

Clients MUST treat handles as untrusted input and always resolve them to DIDs before use.

---

## Invariants Summary

DID is the canonical identity.  
Handles are human-readable aliases.  
Vanity IDs are optional aesthetic choices for opaque identifiers.  
Handles can change; DIDs do not.  
Resolution is web-native, domain-scoped, and decentralized.
