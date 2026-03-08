# GreyThing
### Protocols for portable identity and capability-based access to user-owned data

Status: **working prototype**

Protocol version: draft-v1

Specifications: see `/spec`

Reference implementation: this repository

GreyThing explores protocols where identity is anchored in cryptographic root keys and data is stored in user-controlled storage endpoints, allowing services and agents to access user-authorized data through capability-based mechanisms.

* **Identity belongs to users and can move across domains and providers.**
* **Data lives in user-owned storage and moves with the user across providers.**
* **Services and agents access user-authorized data through capability-based protocols.**

**GreyThing** is an experimental open infrastructure project for **portable identity**, **user-owned storage**, and **capability-based data access**.

GreyThing explores a shift:

> **From platforms to protocols: letting users own identity and data.**

Instead of platforms owning user identities and data, GreyThing investigates an architecture where users control their identity and storage while services interact with that data through open protocols.

---

# Why GreyThing

Today's online platforms tightly couple:

- identity
- data storage
- permissions
- application logic

This creates platform lock-in: users cannot migrate identity or data without losing their social history.

GreyThing explores an alternative architecture:

- identity is **portable**
- data is **user-owned**
- permissions are **cryptographic capabilities**
- services become **data consumers rather than data owners**

identity (DID)
      |
      v
user-owned storage
      |
      v
capability grants
      |
      v
services / AI agents

---

# Core Concepts

GreyThing is built around five architectural principles:

### Portable Identity

Users are identified by **Decentralized Identifiers (DIDs)** anchored in cryptographic root keys.

Identity continuity does not depend on a domain or platform account.

This allows **cross-domain identity migration**: DIDs and associated data can move across domains and hosting providers without losing identity continuity.

### Durable Identity (Revocation & Recovery)

Portability must survive device loss.

GreyThing supports:
- device key rotation and revocation via DID updates
- optional passphrase-protected root key backups
- future guardian-based recovery using **Guardian DIDs** (threshold approvals)

Portable identity is only meaningful if it is recoverable.

---

### User-Owned Storage

User data is stored in **portable storage endpoints**.

Objects are:

- content-addressed
- cryptographically signed
- independent from applications

Users can migrate storage providers without losing data.

User storage may contain both private and public data objects such as messages, encrypted attachments, profile data, application data, public content, or contact relationships.

---

### Capability-Based Access

Access to data is controlled through **signed capability grants**.

A grant is a small cryptographic object authorizing:
* who can access
* which resource
* for how long

Grants can be transmitted alongside requests and verified independently without relying on server-side policy enforcement.

---

### Services as Data Consumers

In GreyThing:
services do not own user data

Instead:
services retrieve user-authorized data from user-owned storage via open protocols


This model also enables interactions with **automated agents and AI systems**.

---

# Architecture Overview

Traditional platforms:
```
identity --|
data      -|-> platform owns storage + permissions + APIs
access    -|
```

GreyThing architecture:
```
identity (DID anchored in root key)
|
|-> user-owned storage
|
|-> capability grants (signed permissions)
|
|-> services & AI agents consume authorized data
```

### Protocol Stack

| Layer | Role |
|------|------|
| Applications & Agents | Messaging, feeds, marketplaces, services |
| Capability Layer | Signed grants controlling access to resources |
| Discovery Layer | Claims-based identity lookup with privacy-preserving hashes |
| Storage Layer | User-owned storage with content-addressed objects |
| Identity Layer | Portable identity anchored in cryptographic root keys |

---

# Identity

GreyThing currently uses the **did:web** method.

Example:
did:web:did.greything.com:u:alice


DID documents contain:

- public keys (Ed25519 for signing, X25519 for key agreement)
- service endpoints (storage, inbox)

GreyThing hosts only **public identity documents**.

GreyThing never stores:

- private keys
- user content

Users can migrate their identity to another domain without changing the identity itself.

---

# Storage

GreyThing uses **portable storage endpoints**.

Storage characteristics:

- content-addressed objects
- cryptographic signatures
- provider-independent
- migratable

Storage endpoints can be operated by:

- individuals
- hosting providers
- organizations
- ordinary websites (via WordPress plugin)

---

# Discovery

Identity discovery uses a **claims-based model** where users publish self-asserted identity claims (name, location, keywords) in their own storage.

Sensitive attributes such as phone numbers and email addresses can be stored as cryptographic hashes, enabling exact-match discovery without exposing plaintext identifiers.

Discovery indexers fetch and cache claims but are not the source of truth -- users control what they publish.

---

# WordPress Integration

GreyThing includes a **WordPress plugin** that allows any website to:

- host DID documents for registered users
- operate GreyThing storage endpoints (blobs, heads, inbox)
- provide a user dashboard with profile editing and cross-domain E2EE messaging

This demonstrates how existing web infrastructure can participate in decentralized identity and storage networks.

> **GreyThing turns ordinary websites into identity and storage nodes.**

Users registered on a WordPress site can exchange end-to-end encrypted messages with users on any other GreyThing node, demonstrating cross-domain interoperability.

---

# Messaging (Demonstration Application)

GreyThing includes a **reference messaging implementation** that demonstrates how the protocol components work together in a real-world use case.

Features:

- end-to-end encrypted messages (X25519 + AES-GCM)
- encrypted attachments stored in user-owned storage
- access to attachments controlled through capability grants
- cross-domain messaging between independent GreyThing nodes
- signature verification of sender identity

Messaging validates the underlying infrastructure but the storage model is not limited to messaging and can support other application data such as public content, contact lists, or private user data.

---

# AI Agents

GreyThing treats **AI agents as external protocol clients**.

Agents may:

- curate feeds
- recommend content
- filter spam
- assist with publishing

Agents interact with user-authorized data through **capability grants and open protocols**.

Agents are **replaceable services**, not platform components.

---

# Security Model

GreyThing uses well-established cryptographic primitives:

- Ed25519 for signatures
- X25519 for key exchange
- AES-GCM for symmetric encryption
- HKDF-SHA256 for key derivation

Private keys are generated and used **client-side only**.

Servers never see signing keys.

Identity lifecycle mechanisms include device key revocation and optional recovery models to ensure identity continuity after device loss.

---

# Design Principles

- **portable identity** -- anchored in cryptographic keys, not domains
- **durable identity** -- key rotation, revocation and recovery ensure identities survive device loss
- **user-owned storage** -- migratable across providers
- **capability-based access** -- signed grants authorize access to specific resources
- **protocol-first architecture** -- open specifications designed for reuse across applications
- **services as consumers** -- services and agents retrieve user-authorized data rather than owning it

---

## Specifications

GreyThing protocol specifications are documented in the `/spec` directory.

- Identity model
- Storage interaction
- Capability grants
- Identity discovery (claims)
- Messaging reference implementation

---

# Current Status

A working prototype exists, including:

- portable DID hosting (`did:web`)
- cross-domain identity discovery through claims
- user-owned storage with content-addressed blobs and mutable heads
- device key revocation mechanisms
- signed capability grants for resource access
- end-to-end encrypted private messaging with signature verification
- encrypted attachments shared through grants
- WordPress plugin enabling any website to host identities and storage
- cross-domain E2EE messaging between independent nodes

Links:
- Working prototype: https://did.greything.com/
- GitHub: https://github.com/mazhurin/greything

---

# Vision

GreyThing explores an internet architecture where:

- users remain custodians of their identity and data
- services interact with user-authorized data through open protocols
- platforms become replaceable protocol clients

Users maintain portable **personal data nodes** containing identity, data and access permissions. These nodes may be hosted by users themselves or by independent service providers while remaining portable across domains and providers.

Such architectures may contribute to a more open and resilient internet where identity and data remain under user control.

---

# License

GreyThing is developed as open infrastructure and will be released as **free and open-source software**.

---

> Build social systems like the web itself: open, portable, and replaceable.
