# DIDD + Claims Specification v1

## Status
- Version: v1
- Status: Draft / MVP-ready
- Scope: Discovery, claims, and verification for DID-based identity systems

---

## 1. Overview

This specification defines a **human-centric discovery layer** for decentralized identities (DID), called **DIDD (Decentralized Identity Discovery)**, together with a **portable, signed claims model**.

The goal is to enable discovery of people, organizations, and services:
- without nicknames,
- without global name scarcity,
- without a central authority,
- while preserving cryptographic identity guarantees.

---

## 2. Core Principles

1. **DID is not a discovery identifier**  
   DID is a stable cryptographic identifier, not meant for human lookup.

2. **Discovery is probabilistic and non-authoritative**  
   Multiple results, duplicates, and ranking are expected.

3. **Claims are portable and user-owned**  
   Claims live in user-controlled storage, not in registries.

4. **Verification is optional and market-based**  
   Trust comes from attestations, not from a single authority.

5. **Privacy by default**  
   Sensitive attributes are matched via hashes unless explicitly made public.

---

## 3. Roles

### 3.1 Subject
An entity identified by a DID (person, organization, service).

### 3.2 Claim Publisher
The subject itself, publishing self-asserted claims.

### 3.3 Verifier
A third-party service issuing signed attestations about specific attributes.

### 3.4 DIDD Provider
A discovery indexer that:
- fetches claims,
- validates signatures,
- indexes and ranks results according to its own policy.

---

## 4. DID Document Requirements

The DID Document (`did.json`) MUST:
- contain verification methods (public keys),
- contain service endpoints,
- NOT contain discovery claims.

A subject MAY publish a `ClaimsService` endpoint:

- `type`: `ClaimsService`
- `serviceEndpoint`: URL to the root of the ClaimSet

---

## 5. Claim Hosting Model

Claims MUST be hosted in **user-controlled storage**, such as:
- Solid Pod,
- personal domain,
- self-hosted storage.

Bootstrap hosting (e.g. GreyThing) MAY be offered but MUST NOT be required.

DIDD providers MAY cache claims but MUST NOT be the source of truth.

---

## 6. ClaimSet Structure

A ClaimSet root MUST contain:

- `manifest.json` (signed)
- claim objects referenced by the manifest

Recommended layout:

- /claims/
  - manifest.json
  - objects/
    - <claim-id>.json
  - revocations/ (optional)

---

## 7. Manifest Format (Mandatory)

The manifest provides integrity, lifecycle control, and efficient ingestion.

Required fields:
- `subject` (DID)
- `createdAt` (RFC3339)
- `expiresAt` (optional)
- `claims[]`:
  - `id`
  - `url`
  - `hash`
  - `type`
  - `scope`
  - `validFrom` / `validTo` (optional)
- `proof` (signature by subject DID key)

DIDD MUST validate:
- manifest signature,
- hash of each referenced claim object.

---

## 8. Claim Object Format

Each claim object MUST include:

- `id`
- `type`
- `subject` (DID)
- `issuedAt`
- `scope` (`public` | `unlisted` | `private`)
- `value`
- `proof` (optional; see modes below)

### Claim Signature Modes

- **Mode A (recommended):**
  - Claim objects are immutable.
  - Manifest signature + hashes provide integrity.

- **Mode B (optional):**
  - Each claim object is individually signed.
  - Manifest MAY still be signed.

DIDD providers MUST support Mode A.

---

## 9. Claim Scopes

- `public`: indexable and visible in broad search
- `unlisted`: usable only for exact-match or contextual lookup
- `private`: MUST NOT be indexed

---

## 10. Standard Claim Types (v1)

### 10.1 PersonDisplayNameClaim
Human-readable name (duplicates allowed).

### 10.2 OrganizationNameClaim
Public organization or business name.

### 10.3 KeywordsClaim
Free-form tags describing activity or role.

### 10.4 LocationClaim (Coarse)
Country / region / city only. No precise addresses.

### 10.5 ContactHintClaim
Privacy-preserving contact hint using salted hash.
Used for exact-match discovery only.

### 10.6 SocialProofClaim
Link to external profile with optional proof URL.

### 10.7 SameAsClaim
Links multiple DIDs belonging to the same subject.
Used for migration and identity continuity.

---

## 11. Phone Number Discovery and Verification

### 11.1 Separation of Concerns

- **Phone hash hint** = discovery mechanism
- **Phone verification** = trust attestation

They are independent.

---

## 12. PhoneControlProofClaim

A third-party attestation confirming control of a phone number.

This claim is signed by the verifier, not the subject.

### 12.1 Mode A — Hash-Based Verification (Default)

- Stores only a phone hash
- Scope: `unlisted`
- Used for incoming-call or contact-based discovery
- MUST support exact-match only
- MUST NOT be enumerable

### 12.2 Mode B — Public Phone Verification (Opt-in)

- Stores plain phone number
- Scope: `public`
- Intended for businesses and public services
- MUST be explicit opt-in

---

## 13. Verification Protocol (Minimal)

1. Subject authenticates with DID.
2. Subject submits phone number.
3. Verifier performs SMS / voice / callback check.
4. Verifier issues `PhoneControlProofClaim`.
5. Subject stores claim in ClaimSet.

All verification claims MUST include:
- `verifiedAt`
- `expiresAt`
- `verifier DID`
- verification method

---

## 14. Verifier Market Model

- Anyone MAY operate a verifier.
- Verifiers identify themselves via DID.
- Claims are portable between DIDD providers.

DIDD providers:
- choose which verifiers to trust,
- assign weights or freshness policies,
- MAY require multiple attestations for higher ranking.

No verifier is globally authoritative.

---

## 15. GreyThing Verifier (Initial MVP)

GreyThing MAY provide a phone verifier service:
- DID: `did:web:greything.com:verifiers:phone`
- Method: SMS OTP
- Output: `PhoneControlProofClaim`

GreyThing MUST NOT:
- store global phone-to-DID mappings,
- modify user DID Documents,
- act as the only trusted verifier.

---

## 16. Extension: Real-World Identity Verification

The same attestation model MAY be extended to:
- government ID verification,
- residence confirmation,
- business registration proof.

Possible future claims:
- `GovernmentIdProofClaim`
- `ResidenceProofClaim`
- `BusinessRegistrationProofClaim`

These enable a “verified account” UX similar to social platforms,
without centralized control.

---

## 17. Revocation and Expiry

- Claims MAY expire via `expiresAt`.
- ClaimSets MAY publish signed revocation lists.
- DIDD SHOULD down-rank expired or revoked claims.

---

## 18. DIDD Search API (Conceptual)

DIDD providers MAY expose search APIs supporting:
- text query
- filters (location, keywords, contact hash)
- ranking explanations
- multiple results

Exact API shape is intentionally not fixed.

---

## 19. Security and Privacy Requirements

- Hash-based discovery MUST be exact-match only.
- Enumeration of phone hashes MUST be prevented.
- Claims MUST be validated cryptographically.
- DIDD MUST respect claim scopes.

---

## 20. Conformance Summary

A conforming system:
- separates DID from discovery,
- keeps claims outside `did.json`,
- supports hash-based phone discovery,
- supports verifier attestations,
- allows competing DIDD and verifier providers.

---

## 21. Summary

DIDD + Claims v1 defines:
- human-first identity discovery,
- cryptographic trust anchors,
- privacy-preserving contact matching,
- open markets for discovery and verification.

This system replaces usernames and central registries
with portable, verifiable, user-owned identity data.
