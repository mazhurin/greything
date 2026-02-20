# gt-didlog-v1 — GreyThing DID History Log

Status: Draft  
Scope: Minimal, verifiable history of DID Document changes  
Non-goals: Federation, consensus, mandatory witnesses

---

 

`gt-didlog-v1` defines a content-addressed, append-only log that records
the evolution of a DID Document over time.

The log is:
- independent of DID hosting domain
- cryptographically verifiable
- survivable across migrations
- discoverable via `did.json`

The DID hosting service (DIDS) only serves the current `did.json`.
All historical versions live in GreyThing storage.

---

## 2. Discovery

The DID Document MUST include a service entry pointing to the DID log.

Example (illustrative, non-normative):

{
  "service": [{
    "id": "#didlog",
    "type": "GreyThingDIDLog",
    "serviceEndpoint": "https://storage.greything.org/objects/urn:gt:didlog:abc123",
    "profile": "urn:gt:didlog:v1"
  }]
}

The `serviceEndpoint` is a gateway to content-addressed log objects.

---

## 3. Log Structure

The DID log is a hash-linked chain of immutable entries.

Each entry:
- is content-addressed (hash = object ID)
- links to the previous entry
- is signed by the current controlling key
- refers to a specific DID Document version

### Entry types

- Genesis — first entry
- Update — DID Document change
- Recovery — change of controlling key(s)

---

## 4. Log Entry Format

Canonical encoding: JSON Canonicalization Scheme (JCS)  
Signature scheme: Ed25519

Example entry (illustrative):

{
  "type": "Update",
  "did": "did:web:greything.com:users:alice",
  "prev": "zQmPrevEntryHash",
  "didDocHash": "zQmDidDocHash",
  "createdAt": "2026-02-10T12:34:56Z",
  "meta": {
    "reason": "rotate-device-keys"
  },
  "controller": "did:web:greything.com:users:alice#control-2026",
  "signature": {
    "alg": "Ed25519",
    "kid": "did:web:greything.com:users:alice#control-2026",
    "sig": "zSignatureBase58"
  }
}

---

## 5. Genesis Entry

- `prev` MUST be null
- establishes initial controlling key(s)
- anchors the first DID Document hash

The first entry in the log MUST be of type `Genesis`.

---

## 6. Recovery Entry

A `Recovery` entry changes the controlling key set.

Rules:
- MUST be signed by a valid recovery authority
- MUST declare new controlling key(s)
- Subsequent entries MUST be signed by the new controller

Example field:

{
  "type": "Recovery",
  "newController": "did:web:greything.com:users:alice#control-2027"
}

At this point, validation switches trust to the new controller.

---

## 7. Validation Rules

A client validating a DID MUST:

1. Resolve `did.json`
2. Locate the `GreyThingDIDLog` service
3. Fetch the log head
4. Walk the chain via `prev`
5. Verify:
   - hash integrity
   - signature correctness
   - controller continuity (including Recovery handling)
6. Confirm that the latest `didDocHash`
   matches the resolved `did.json`

If a mismatch is detected, the DID MUST be considered inconsistent.

---

## 8. Minimal Gateway API

A DID log gateway SHOULD support:

- GET {endpoint}/head  
  Returns the hash of the latest entry

- GET {endpoint}/obj/{hash}  
  Returns the raw log entry

No pagination, indexing, or search is required.

---

## 9. Security Notes

- The log provides auditability, not availability
- Independent witnesses MAY publish timestamp attestations
  referencing log entry hashes
- Loss of all recovery keys permanently freezes the log

---

## 10. Design Principles

- DIDS remains minimal and stateless
- History is user-owned and portable
- No mandatory federation
- Verification is client-side
- Logs are neutral storage objects

