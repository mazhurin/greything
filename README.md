# GreyThing

**GreyThing** is a decentralized social network focused on **user-owned identity**, **portable data**, and **replaceable intelligence**.

GreyThing is not a platform that owns users.
It is infrastructure that helps users connect — without lock‑in.

---

## Why GreyThing

Today’s social networks:

* own user identities
* lock data inside centralized databases
* monetize attention and behavior
* cannot be left without losing social history

GreyThing takes a different approach:

> **Users own themselves. Platforms provide services, not control.**

---

## Core Ideas

* **Portable identity** — users are identified by DIDs, not accounts
* **User-owned data** — content lives in personal Solid Pods
* **No lock-in** — storage, feeds, and AI can be replaced
* **Pluggable intelligence** — AI agents compete, users choose
* **Web2 UX, Web3 guarantees** — decentralization without friction

---

## Architecture at a Glance

GreyThing is built from four independent layers:

1. **Identity layer** — Decentralized Identifiers (DID)
2. **Storage layer** — Solid Pods
3. **Discovery layer** — Event streams & indexes
4. **Intelligence layer** — External AI agents

Each layer can evolve independently.

---

## Identity (DID)

* GreyThing provides **free DID hosting** at project start
* DID method: `did:web`
* Example:

  ```
  did:web:greything.com:users:alice
  ```

GreyThing hosts **only DID Documents**:

* public keys
* service endpoints

GreyThing **never stores**:

* private keys
* user content

Users can later migrate their identity to their own domain.

---

## Data & Storage (Solid Pods)

Each user owns a **Solid Pod** containing:

* posts and media
* social graph
* signed likes and comments
* profile data
* encrypted key backups

Pods are:

* provider-independent
* fully migratable
* controlled by the user

---

## Discovery

GreyThing does not rely on a single global feed.

Discovery is handled via:

* short-lived event streams (TTL-based)
* optional peer-to-peer discovery
* competing feed and search providers
* social discovery through follows

Anyone can build a feed or indexer.

---

## AI Agents

AI agents are **external services**, not part of the core platform.

They can:

* curate feeds
* recommend content and users
* filter spam and abuse
* assist with publishing

Agents operate via explicit permissions and can be replaced at any time.

---

## Security & Keys (High Level)

* Private keys are generated and used **client-side only**
* GreyThing never sees signing keys
* Solid Pods may store **encrypted backups**, never usable keys
* Identity recovery is opt-in and multi-party

---

## Monetization

GreyThing does **not monetize identity**.

Free:

* basic DID hosting
* basic Solid Pod storage

Paid services include:

* additional storage and bandwidth
* SLA-backed DID hosting
* custom domain identities
* advanced recovery services
* enterprise and organization accounts

Users pay for **resources and convenience**, not existence.

---

## Project Status

GreyThing is an **early-stage project**.

Current focus:

* architecture
* security model
* developer experience

This repository documents the design and direction of the project.

---

## Philosophy

GreyThing is infrastructure.

It does not:

* own user data
* control social graphs
* lock users into proprietary systems

If GreyThing disappears, users keep:

* their identity
* their data
* their relationships

---

## Learn More

* See **GREYTHING.md** for the full project vision and architecture
* Additional documents will cover threat models, recovery flows, and APIs

---

> **Build social networks like the web itself: open, portable, and replaceable.**
