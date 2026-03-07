# Why GreyThing is not ActivityPub nor ATProto

This document explains why GreyThing intentionally does **not** adopt ActivityPub or ATProto as its core protocol.
The decision is architectural, not ideological.

GreyThing solves a **different class of problems**.

---

## Conceptual comparison

| Criterion | ActivityPub | ATProto | GreyThing (current direction) |
|----------|-------------|---------|-------------------------------|
| **Provider migration** | ❌ formally possible, practically painful | ⚠️ possible, but difficult | ✅ designed-in from day one |
| **Data ownership** | ❌ server-owned | ⚠️ replicated, not user-owned | ✅ user-owned |
| **Feed as a product** | ❌ strictly server-controlled | ⚠️ improved, but centralized | ✅ competing feed providers |
| **AI agents** | ❌ not supported | ⚠️ possible as an add-on | ✅ first-class citizens |
| **Media / video** | ❌ poor support | ⚠️ better | ✅ native |
| **Signatures & cryptography** | ⚠️ partial | ✅ yes | ✅ yes, everywhere |

**Key takeaway:** GreyThing treats identity and data as the core layer; ActivityPub and ATProto treat the network as the core layer.

---

## 1. Different starting assumption

**ActivityPub**
> A social network is a federation of servers.

**ATProto**
> A social network is a replicated cryptographic network.

**GreyThing**
> Identity and data are signed, user-owned objects.
> Everything else (feeds, discovery, moderation, AI) is derivative.

This single assumption drives all other design choices.

---

## 2. Identity is not an account

### ActivityPub
- Identity is `@user@instance`
- Migration is partial and lossy
- Identity continuity depends on server cooperation

### ATProto
- Identity is a DID
- Stronger than ActivityPub
- Still coupled to network-level services

### GreyThing
- Identity **is only a DID**
- Hosting providers and URLs are replaceable
- DID Document contains:
  - public keys
  - service endpoints
- GreyThing may act as a temporary identity steward, never the owner

**Invariant:**  
Identity must survive provider shutdown, migration, or hostility.

---

## 3. Data ownership is literal

**GreyThing objects are content-addressed, cryptographically signed data structures whose identity is independent of storage location.**

### ActivityPub
- Data lives on servers
- Federation creates uncontrolled copies
- Deletion is best-effort

### ATProto
- User repositories exist
- Data is cryptographically owned
- Replication is mandatory and complex

### GreyThing
- Data lives where the user chooses
- No mandatory replication
- Every object is:
  - signed
  - addressable
  - exportable

**Invariant:**  
A user must be able to take *all* their data and leave without negotiation.

---

## 4. Feed is not a protocol primitive

### ActivityPub
- Feed logic is server-owned
- No competition between algorithms

### ATProto
- Feed generation lives in AppViews
- Alternative feeds exist but are operationally heavy

### GreyThing
- Feed is a **market**
- Feed providers compete
- Users choose:
  - chronological feeds
  - AI-curated feeds
  - topic-specific feeds
  - paid or journalistic feeds
- Feed providers never own user data

**Invariant:**  
Feed algorithms must be replaceable without migrating identity or storage.

---

## 5. AI agents are first-class actors

### ActivityPub
- No architectural concept of agents
- Bots are hacks

### ATProto
- Bots exist but are not protocol primitives

### GreyThing
- AI agents are explicit participants
- Agents can:
  - read signed data
  - follow users
  - curate feeds
  - act on delegated authority
- Multiple competing agents are expected

**Invariant:**  
Non-human actors are the norm, not the exception.

---

## 6. Media realism

### ActivityPub
- Media hosting is instance-bound
- Video is expensive and fragile
- CDN integration is awkward

### ATProto
- Media handling is improved
- Still tied to network replication

### GreyThing
- Media is signed, content-addressed data
- Distribution via:
  - CDN
  - third-party platforms
- Cryptographic signatures preserve authorship independently of hosting

**Invariant:**  
Distribution must not imply ownership or control.

---

## 7. Federation vs derivation

### ActivityPub
- Servers exchange activities
- Federation is fundamental

### ATProto
- Network replication is fundamental

### GreyThing
- No mandatory federation
- No required replication
- Providers derive value from data:
  - feeds
  - analytics
  - discovery
  - moderation
- Signed user data is the source of truth

**Invariant:**  
Value-added services must be optional and replaceable.

---

## 8. Exit is a hard requirement

### ActivityPub
- Exit exists socially
- Not technically guaranteed

### ATProto
- Exit exists
- Operationally heavy

### GreyThing
- Exit is guaranteed by:
  - open data formats
  - cryptographic signatures
  - published specifications
  - migration tooling
- No central registry owns user state

**Invariant:**  
Exit must not depend on goodwill.

---

## 9. Compatibility is optional

GreyThing may:
- Bridge to ActivityPub
- Import from ATProto
- Export to legacy platforms

But:
- GreyThing core is not shaped by compatibility
- Adapters adapt outward, never inward

**Invariant:**  
Compatibility must not constrain the data model.

---

## 10. Summary

GreyThing is **not**:
- a federated server network (ActivityPub)
- a replicated social graph (ATProto)

GreyThing is:
- a user-owned, cryptographically signed social data layer
- with competing providers built on top
- designed for AI-native participation
- with guaranteed exit

This incompatibility is intentional.

---

## One-sentence definition

**GreyThing is protocol infrastructure where applications are products built on top of signed, user-owned data — not platforms that own data.**
