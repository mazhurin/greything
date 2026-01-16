# How to Create a DID, Generate Keys, and Publish Your First Signed Post (Prototype)

This guide walks through the **manual, step-by-step** flow to:

1. Start the prototype services
2. Generate keys
3. Create a `did:web` identity (DID)
4. Attach service endpoints (pod + events + profile)
5. Add a device key to the DID Document
6. Sign a post with the device key
7. Store the post in the pod-mock
8. Verify the post signature via DID resolution

> This is a **development prototype**. Do not use these tools or key files for production.

---

## Prerequisites

* Go installed (recommended: Go 1.22+)
* `curl`
* `jq`

From the repository root:

```bash
go test ./...
```

---

## 1) Start the Prototype Services

Open **three terminals** and run:

### Terminal A — DID registry

```bash
go run ./cmd/did-registry
```

The registry listens on:

* `http://localhost:8080`

### Terminal B — pod-mock storage

```bash
go run ./cmd/pod-mock
```

The pod-mock listens on:

* `http://localhost:8081`

### Terminal C — event-stream (optional for first post)

```bash
go run ./cmd/event-stream
```

The event-stream listens on:

* `http://localhost:8082`

---

## 2) Generate the Root Key (Public Key for DID)

The DID registry needs your **root public key** in multibase base58btc (`z...`).

Generate it using `gt-keygen`:

```bash
go run ./cmd/gt-keygen --kid root --out .greything/keys/anton-root.json
```

Output example:

```
KID: root
PublicKeyMultibase: z6M...
Saved private key to: .greything/keys/anton-root.json
```

> In this prototype the root private key is stored locally in a JSON file.
> In a real client, the root private key should be stored in OS secure storage / hardware key store.

---

## 3) Create a New DID for User `anton`

Create a DID entry in the DID registry using your root public key:

```bash
curl -sS -X POST http://localhost:8080/v1/users \
  -H 'Content-Type: application/json' \
  -d "{\
    \"username\": \"anton\",\
    \"rootPublicKeyMultibase\": \"$(jq -r .publicKeyMultibase .greything/keys/anton-root.json)\"\
  }" | jq .
```

Expected output:

```json
{
  "did": "did:web:greything.com:users:anton",
  "didDocumentUrl": "http://localhost:8080/users/anton/did.json"
}
```

Fetch the DID Document:

```bash
curl -sS http://localhost:8080/users/anton/did.json | jq .
```

---

## 4) Attach Service Endpoints (Pod + Events + Profile)

Attach your pod and event endpoints to the DID Document.

For the local prototype:

* pod-mock: `http://localhost:8081/u/anton/`
* events: `http://localhost:8082/v1/events`
* profile (example): `http://localhost:8081/u/anton/profile.json`

Run:

```bash
curl -sS -X PUT http://localhost:8080/v1/users/anton/services \
  -H 'Content-Type: application/json' \
  -d '{
    "pod": "http://localhost:8081/u/anton/",
    "events": "http://localhost:8082/v1/events",
    "profile": "http://localhost:8081/u/anton/profile.json"
  }' | jq .
```

Verify that services appear in the DID Document:

```bash
curl -sS http://localhost:8080/users/anton/did.json | jq .service
```

---

## 5) Generate a Device Key

Daily actions (posts, likes, comments) should be signed with a **device key**, not the root key.

Generate a device key:

```bash
go run ./cmd/gt-keygen --kid device-2026-01-10 --out .greything/keys/anton-device-2026-01-10.json
```

---

## 6) Add the Device Public Key to the DID Document

Publish the device **public key** so verifiers can validate signatures.

```bash
curl -sS -X PUT http://localhost:8080/v1/users/anton/device-keys \
  -H 'Content-Type: application/json' \
  -d "{\
    \"deviceKeyId\": \"device-2026-01-10\",\
    \"publicKeyMultibase\": \"$(jq -r .publicKeyMultibase .greything/keys/anton-device-2026-01-10.json)\"\
  }" | jq .
```

Verify that the new verification method exists:

```bash
curl -sS http://localhost:8080/users/anton/did.json \
 | jq '.verificationMethod[] | select(.id|endswith("#device-2026-01-10"))'
```

---

## 7) Sign Your First Post

Use `gt-sign-post` to create a signed `Post` JSON.

```bash
go run ./cmd/gt-sign-post \
  --key .greything/keys/anton-device-2026-01-10.json \
  --author did:web:greything.com:users:anton \
  --content 'Hello GreyThing - first signed post!' \
  --out /tmp/anton-post.json
```

Inspect the signed post:

```bash
cat /tmp/anton-post.json | jq .
```

---

## 8) Store the Post in the Pod (pod-mock)

Upload the post JSON to pod-mock under object id `firstpost`:

```bash
curl -sS -X PUT http://localhost:8081/u/anton/objects/firstpost \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/anton-post.json
```

Read it back:

```bash
curl -sS http://localhost:8081/u/anton/objects/firstpost | jq .
```

---

## 9) Verify the Post Signature via DID Resolution

Use `gt-verify-post` to verify that:

* the post is signed by the device key
* the device key is published in the author DID Document

Run:

```bash
go run ./cmd/gt-verify-post --post http://localhost:8081/u/anton/objects/firstpost
```

Expected output:

```
OK: signature valid
Post: urn:gt:post:...
Author: did:web:greything.com:users:anton
KID: did:web:greything.com:users:anton#device-2026-01-10
```

---

## Notes and Next Steps

* This prototype uses a simple canonical string format for signing.
* The next milestone is to sign and publish an **event** (`new_post`) to `event-stream`, and have indexers build a feed.
* For production, key storage and recovery must use secure OS mechanisms, encrypted backups, and explicit user recovery flows.
