# DIDS — Decentralized Identity Domain Services (v1)

This document defines **DIDS (Decentralized Identity Domain Services)** — a domain-based identity
naming and resolution model used by GreyThing.

DIDS provides a web-native, decentralized alternative to global username registries by delegating
human-readable identity naming to domain owners, in a manner analogous to DNS and email.

---

## Motivation

Global username systems inevitably create conflicts, squatting, centralized control, and
arbitration problems.

GreyThing avoids these issues by separating:

- Canonical identity (DID)
- Human-readable names (DID names / handles)
- Infrastructure responsibility (domain operators)

DIDS enables identity naming through domain ownership, not global registries.

---

## Core Idea

A **DID Identity Service (DIDS)** is any domain that:

- owns a DNS name
- serves content over HTTPS
- hosts DID Documents (did.json)
- resolves human-readable DID names to DIDs

There is no central authority and no global registry of names.

Any domain can become a DIDS.

---

## Analogy with DNS and Email

DNS / Email → DIDS

- Domain name → DID Service domain  
- Email address (alice@example.com) → DID name (alice@example.com)  
- DNS + MX records → /.well-known/greything/resolve  
- TLS certificate → DID Document (did.json)  
- Email provider → DID Service provider  

Just as anyone can run an email server for their domain, anyone can run a DIDS.

---

## Accessibility for Ordinary Domain Owners

A core design goal of DIDS is a very low barrier to entry.

An ordinary person who owns a domain name can create a DIDS by:

1. Pointing the domain to any HTTPS-capable hosting.
2. Serving static JSON files over HTTPS.
3. Exposing a simple well-known HTTP endpoint for name resolution.

No blockchain, no special infrastructure, no trusted intermediaries are required.

A DIDS can be implemented using:

- shared hosting
- a small VPS
- object storage (S3, R2, B2)
- static site hosting
- standard TLS certificates (e.g. Let’s Encrypt)

In its simplest form, a DIDS is a static website.

---

## Responsibilities of a DIDS

A DIDS MAY provide:

- Hosting of DID Documents (did.json)
- Resolution of DID names to DIDs
- Optional provisioning services (user registration, handle assignment)
- Optional policy enforcement (rate limits, reserved names)

A DIDS MUST NOT:

- Hold or manage user private keys
- Sign user-generated content
- Act as a global authority for identity truth

---

## DID Names

A DID name has the form:

name@domain

Example:

alice@greything.com

Properties:

- DID names are human-readable aliases
- DID names are mutable
- DID names are scoped to a domain
- Uniqueness is required only within a domain

At any given time, a DID name resolves to exactly one DID.

---

## DID Name Resolution

DID names are resolved via HTTPS requests to the domain.

Canonical endpoint:

GET https://<domain>/.well-known/greything/resolve?name=<name>

Example response:

{
  "name": "alice@greything.com",
  "did": "did:web:did.greything.com:u:3x9f2k7m"
}

Resolution is a convenience mechanism and not a security primitive.

---

## Canonical Identity and DID Hosting

Canonical identity is expressed via DIDs, typically using the did:web method.

Example DID:

did:web:did.greything.com:u:3x9f2k7m

DID Documents MUST be retrievable as static JSON files.

Example location:

https://did.greything.com/u/3x9f2k7m/did.json

DID resolution MUST NOT depend on any DIDS API or dynamic service.

---

## Migration and Portability

Users are not locked into a single DIDS.

- Handles can change without changing the DID
- Domains can migrate identities using signed migration claims
- HTTP redirects may assist UX but are not sufficient proof of migration

This ensures long-term identity portability and exit guarantees.

---

## Market Dynamics

DIDS form a competitive, open market.

Domains may differentiate on:

- brand and memorability
- pricing
- jurisdiction and legal guarantees
- privacy policy
- UX and tooling
- integration with feeds and AI agents

GreyThing does not bless, rank, or authorize DIDS providers.

---

## Security Model

- Trust is anchored in cryptographic keys, not domains
- Domains provide discovery and convenience, not authority
- DID Documents define verification keys
- DIDS compromise does not invalidate existing signatures

---

## Summary

- DIDS are domain-based identity services
- Any HTTPS-enabled domain can become a DIDS
- Human-readable names are scoped to domains
- Canonical identity is expressed via DIDs
- Naming is decentralized, competitive, and market-driven

DIDS provides a practical, web-native foundation for human identity without global registries.
