# GreyThing — Protocol Infrastructure for Portable Identity and User-Owned Data

## 1. Vision

GreyThing is an experimental infrastructure project exploring protocols for **portable identity**, **user-owned storage**, and **capability-based data access**.

Our core belief:

> Identity and data must belong to the user. Platforms should provide infrastructure and intelligence, not ownership or lock-in.

GreyThing aims to combine Web2-level usability with Web3-level sovereignty — without forcing users to understand cryptography or buy domains on day one.

---

## 2. Core Principles

1. **User sovereignty** — users own their identity, keys, and data
2. **No platform lock-in** — users can migrate storage, agents, and providers
3. **Minimal trust** — GreyThing never holds signing keys or user content
4. **Replaceable intelligence** — AI agents compete, users choose
5. **Gentle onboarding** — Web2 UX first, decentralization under the hood

---

## 3. Architecture Overview

GreyThing consists of four independent layers:

1. **Identity layer** — Decentralized Identifiers (DID)
2. **Storage layer** — Solid Pods
3. **Discovery layer** — Event streams & indexes
4. **Intelligence layer** — External AI agents

Each layer can evolve or be replaced independently.

---

## 4. Identity Layer (DID)

### 4.1 DID Strategy

* GreyThing provides **free DID hosting** at project start
* DID method: `did:web`
* Example:

  ```
  did:web:greything.com:users:username
  ```

GreyThing hosts **only DID Documents**, never user data or signing keys.

GreyThing acts as a **temporary identity steward**, not an identity owner.

---

### 4.2 DID Document Contents

A DID Document contains:

* Public verification keys
* Service endpoints (pod, inbox, events, profile)
* Optional recovery / migration metadata

It must be:

* Small
* Rarely changing
* Free of user content

---

### 4.3 DID Migration

Users can:

* Change Solid Pod providers by updating service endpoints
* Later migrate to their **own domain DID**

Migration is handled via:

* DID linking (`alsoKnownAs`)
* or HTTP redirect (pragmatic fallback)

Identity continuity is preserved.

---

## 5. Key Management & Security

### 5.1 Key Types

GreyThing uses a **multi-tier key model**:

1. **Root identity key**

   * Signs DID Document
   * Used for key rotation and recovery
   * Generated and stored client-side only

2. **Device / session keys**

   * Used for daily actions (posts, likes, comments)
   * Delegated from root key
   * Short-lived and replaceable

3. **Encrypted backup key**

   * Encrypted copy of root key
   * Stored in Solid Pod
   * Encrypted client-side with user password

---

### 5.2 What GreyThing Never Does

* ❌ Never sees private signing keys
* ❌ Never stores usable keys
* ❌ Never signs content on behalf of users
* ❌ Never recovers identity unilaterally

---

### 5.3 Recovery

Recovery options (opt-in):

* Encrypted backup + password
* Seed / recovery phrase (offline)
* Device-to-device authorization
* Social or service-assisted recovery (multi-party)

GreyThing may assist recovery orchestration, but is never the sole authority.

---

## 6. Storage Layer (Solid Pods)

Each user has a Solid Pod containing:

* Posts and media
* Social graph (follows)
* Signed likes and comments
* Profile data
* Encrypted key backups
* AI agent memory (optional)

Pods are:

* User-owned
* Provider-independent
* Fully migratable

---

## 7. Discovery Layer

GreyThing does not rely on a single global index.

Discovery is achieved via:

* Short-lived **event streams** (TTL-based)
* Optional DHT / p2p discovery
* Competing feed and search index providers
* Social discovery via follows and reposts

Anyone can build a discovery or feed provider.

---

## 8. Intelligence Layer (AI Agents)

AI agents are **external, replaceable services**.

Agents may:

* Curate feeds
* Recommend users and content
* Filter spam and abuse
* Assist with writing and publishing

Agents:

* Operate via explicit permissions
* Do not own user data
* Can store memory in user pods

Users are free to change agents at any time.

---

## 9. Monetization Model

### 9.1 Free Forever

* Basic DID hosting on `greything.com`
* Basic Solid Pod (small storage)
* Core social functionality

Identity is **never monetized**.

---

### 9.2 Paid Services

Users pay for **resources and convenience**, not existence:

* Additional pod storage & bandwidth
* SLA-backed DID hosting
* Custom domain DIDs
* Advanced recovery services
* High-volume event publishing
* AI agent subscriptions
* Enterprise / organization accounts

---

## 10. Trust Model

GreyThing is trusted for:

* Infrastructure availability
* Correct DID resolution
* Transparency

GreyThing is **not** trusted with:

* Keys
* Content ownership
* Signing authority

If GreyThing disappears, users retain:

* Their keys
* Their pods
* Their identity (via migration)

---

## 11. Non-Goals

GreyThing explicitly does NOT aim to:

* Be a centralized social graph
* Monetize attention or data
* Lock users into proprietary clients
* Replace the open web

GreyThing is infrastructure, not a walled garden.

---

## 12. Summary

GreyThing provides:

* A gentle path from Web2 to Web3
* Portable identity without crypto pain
* User-owned data and intelligence
* A competitive ecosystem of agents and services

> Users own themselves. GreyThing just helps them connect.
