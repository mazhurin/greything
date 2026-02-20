



GreyThing guarantees identity and exit for free.
Availability, storage scale, and intelligence are paid services.

GreyThing does not require user-hosted storage.
It requires user-controlled, cryptographically verifiable storage with a guaranteed exit.

GreyThing storage does not require permanent public reachability; availability is a service property, not an identity or ownership property.

GreyThing Storage is a minimal content-addressed blob store.
It stores immutable objects by hash, provides retrieval by identifier,
and makes no assumptions about object semantics, identity, or availability guarantees.


By default, GreyThing provides an authenticated authoritative storage.
Users may migrate to any other storage by copying their data and updating the storage service entry in their DID Document.

GreyThing does not persist events as a primary data structure.
The authoritative record of change is the evolution of signed manifests.
Runtime events are optional and recoverable.

v1 provides content confidentiality (E2EE) and sender authenticity.
v1 does not aim to hide traffic metadata (timing, volume) or the mere existence of messages.


## Storage Availability and Cost — Final Position

GreyThing assumes that **core user storage is always available**, while being **intentionally small, simple, and inexpensive**.

The always-on storage layer is limited to:
- DID documents and service endpoints  
- small, signed social objects (posts, replies, likes, follows)  
- append-only activity and index logs  

All objects in this layer are **small, immutable, content-addressed, and cryptographically signed**, which allows them to be hosted on **commodity storage** (basic HTTP hosting, S3-compatible buckets, low-cost providers) without requiring trust in the hosting provider.

**Large media (images, video, files) is explicitly out of scope for the core storage layer** and may be hosted separately, under different availability, cost, and monetization models.

This design ensures that:
- the system functions without mandatory relay services  
- storage costs remain predictable and low for users  
- availability is sufficient for pull-based feeds and discovery  
- performance acceleration (caching, mirroring, low-latency delivery) is optional and market-driven  

In GreyThing, **storage is a commodity, not a platform lock-in**, and **performance enhancements are competitive services**, not protocol requirements.