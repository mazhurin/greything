# GreyThing Architecture

This document describes the **technical architecture** of GreyThing and how its main components interact.

The goal of this architecture is to provide:

* portable identity
* user-owned data
* decentralized discovery
* replaceable intelligence

While remaining practical to implement and operate.

---

## 1. High-Level System View

GreyThing is composed of **four loosely coupled layers**:

1. Identity Layer (DID)
2. Storage Layer (Solid Pods)
3. Discovery Layer (Events & Indexes)
4. Intelligence Layer (AI Agents)

No single layer has global authority.

---

## 2. Identity Layer

### 2.1 Decentralized Identifiers (DID)

GreyThing uses `did:web` as the initial DID method.

Example:

```
did:web:greything.com:users:alice
```

The DID resolves to a **DID Document** hosted by GreyThing:

```
https://greything.com/users/alice/did.json
```

GreyThing hosts only DID Documents and acts as an **identity bootstrap provider**.

---

### 2.2 DID Document Responsibilities

A DID Document contains:

* Public verification keys
* Authentication and delegation methods
* Service endpoints

It does NOT contain:

* Private keys
* User content
* Personal data

The DID Document is the **root of identity**, not a profile.

---

### 2.3 DID Migration

Users may:

* Change Solid Pod providers
* Later migrate to a custom domain DID

Migration is handled by:

* Updating service endpoints
* DID linking (`alsoKnownAs`)
* Optional HTTP redirect

Identity continuity is preserved across migrations.

---

## 3. Key Management Model

### 3.1 Key Types

GreyThing uses a multi-tier key architecture:

1. **Root Identity Key**

   * Ed25519
   * Signs DID Documents
   * Used for rotation and recovery

2. **Device / Session Keys**

   * Short-lived
   * Used for daily actions
   * Delegated from root key

3. **Encrypted Backup Key**

   * Encrypted copy of root key
   * Stored in Solid Pod

---

### 3.2 Key Storage Rules

* Root private key:

  * Generated client-side
  * Never leaves the client in plaintext

* Device keys:

  * Stored in local secure storage

* Backup key:

  * Encrypted client-side
  * Stored in Solid Pod

GreyThing never has access to usable private keys.

---

### 3.3 Signing Flow

1. User action (post, like, comment)
2. Client signs payload using device key
3. Signed content stored in Solid Pod
4. Verifiers resolve DID and validate signature chain

---

## 4. Storage Layer (Solid Pods)

Each user owns a Solid Pod that stores:

* Content (posts, media)
* Social graph
* Signed interactions
* Profile data
* Encrypted key backups
* Optional AI agent memory

Pods are accessed via URLs referenced in the DID Document.

Pods are fully migratable.

---

## 5. Discovery Layer

### 5.1 Event Streams

GreyThing uses **short-lived event streams** for discovery.

Events may include:

* New post
* New comment
* Profile update

Events:

* Have a limited TTL
* Do not contain full content
* Reference authoritative pod URLs

---

### 5.2 Index Providers

Any party may operate:

* Feed indexers
* Search services
* Topic aggregators

Index providers subscribe to event streams and build their own indexes.

Users choose which providers to trust.

---

## 6. Intelligence Layer (AI Agents)

AI agents are external services that operate via permissions.

Agents may:

* Read user content
* Write recommendations
* Curate feeds
* Store memory in user pods

Agents do not own data and can be replaced at any time.

---

## 7. Request Flow Examples

### 7.1 Reading a User Profile

1. Client resolves user DID
2. Retrieves DID Document
3. Reads profile service endpoint
4. Fetches profile from Solid Pod

---

### 7.2 Publishing Content

1. Client signs content
2. Stores content in Solid Pod
3. Emits discovery event
4. Indexers update feeds

---

### 7.3 Pod Migration

1. User copies data to new pod provider
2. Updates service endpoints in DID Document
3. Indexers re-resolve DID
4. New pod becomes authoritative

---

## 8. Trust Boundaries

GreyThing is trusted for:

* DID Document availability
* Infrastructure correctness

GreyThing is NOT trusted for:

* Key custody
* Content integrity
* Identity recovery alone

Trust is minimized and explicit.

---

## 9. Failure Modes

### 9.1 Pod Compromise

* Content confidentiality may be affected
* Identity remains secure
* Keys are not exposed

---

### 9.2 GreyThing Unavailable

* Existing pods continue functioning
* Identities can be migrated
* No central dependency remains

---

## 10. Summary

GreyThing architecture separates:

* identity from storage
* storage from discovery
* discovery from intelligence

This separation enables:

* portability
* competition
* long-term resilience

GreyThing provides infrastructure, not control.
