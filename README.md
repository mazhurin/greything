# GreyThing

**GreyThing** is an experimental open infrastructure project for **portable identity**, **user-owned storage**, and **capability-based data access**.

GreyThing explores a shift:

> **From platforms to protocols: letting users own identity and data.**

Instead of platforms owning user identities and data, GreyThing investigates an architecture where users control their identity and storage while services interact with that data through open protocols.

---

# Why GreyThing

Today’s online platforms tightly couple:

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

---

# Core Concepts

GreyThing is built around four architectural principles:

### Portable Identity

Users are identified by **Decentralized Identifiers (DIDs)** anchored in cryptographic root keys.

Identity continuity does not depend on a domain or platform account.

This allows **cross-domain identity migration**.

---

### User-Owned Storage

User data is stored in **portable storage endpoints**.

Objects are:

- content-addressed
- cryptographically signed
- independent from applications

Users can migrate storage providers without losing data.

---

### Capability-Based Access

Access to data is controlled through **signed capability grants**.

A grant is a small cryptographic object authorizing:
* who can access
* which resource
* for how long


Grants can be transmitted alongside requests and verified independently.

---

### Services as Data Consumers

In GreyThing:
services do not own user data

Instead:
services retrieve user-authorized data from user-controlled storage via open protocols


This model also enables interactions with **automated agents and AI systems**.

---

# Architecture Overview

Traditional platforms:
identity ─┐
data      ├─► platform owns storage + permissions + APIs
access    ┘

GreyThing architecture:
identity (DID anchored in root key)
│
├─► user-owned storage
│
├─► capability grants (signed permissions)
│
└─► services & AI agents consume authorized data


---

# Identity

GreyThing currently uses the **did:web** method.

Example:
did:web:did.greything.com:u:alice


DID documents contain:

- public keys
- service endpoints

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
- websites

---

# WordPress Integration

GreyThing includes a **WordPress plugin** that allows websites to:

- host DID documents
- operate GreyThing storage endpoints

This demonstrates how existing web infrastructure can participate in decentralized identity and storage systems.

> **GreyThing turns ordinary websites into identity and storage nodes.**

---

# Messaging (Demonstration Application)

GreyThing includes a **reference messaging implementation** that demonstrates how the architecture works.

Features:

- end-to-end encrypted messages
- encrypted attachments
- attachments stored in user storage
- access controlled through capability grants

Messaging is implemented as a **demonstration application** for the underlying infrastructure.

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

# Security Model (High Level)

GreyThing uses well-established cryptographic primitives:

- Ed25519 for signatures
- X25519 for key exchange
- AES-GCM for encryption

Private keys are generated and used **client-side only**.

Servers never see signing keys.

Storage endpoints may store **encrypted backups**, never usable keys.

---

# Design Principles

GreyThing follows several design principles:

- **portable identity**
- **user-owned storage**
- **capability-based access**
- **protocol-first architecture**
- **interoperability between services**
- **replaceable intelligence**

---

# Project Status

GreyThing is an **early-stage experimental infrastructure project**.

Current focus:

- architecture validation
- protocol design
- reference implementation
- developer documentation

---

# Vision

GreyThing explores an internet architecture where:

- users remain custodians of their identity and data
- services interact with user-authorized data
- platforms become replaceable protocol clients

Such architectures may contribute to a more open and resilient internet where identity and data remain under user control.

---

# License

GreyThing is developed as open infrastructure and will be released as **free and open-source software**.

---

> Build social systems like the web itself: open, portable, and replaceable.