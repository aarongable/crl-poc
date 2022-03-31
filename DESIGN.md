# Certificate Revocation List Requirements and Design

## Background

Today there are two technologies for asserting that a WebPKI certificate has been revoked: the Online Certificate Status Protocol (OCSP) and Certificate Revocation Lists (CRLs). Both are specified by IETF standards, and compliance with at least one of the two standards is mandated by the CA/B Forum’s Baseline Requirements. Neither works.

OCSP is broken for reasons outside the scope of this document. But CRLs fail simply because they are so large and unwieldy that most clients just don’t want to download and store them.

Apple and Mozilla are implementing a solution in which CRLs, rather than being downloaded by the client on an ad-hoc basis, are provided directly by the client authors. In order to do so efficiently, they need a way to collect and collate CRLs from CAs. So they are requiring – with an effective date of Oct 1, 2022 – that CAs stand up infrastructure to sign and serve CRLs for all of their end-entity certs, and provide a list of those CRLs directly in CCADB, the Mozilla-managed database in which CAs disclose details about their issuing certificates.

In order to mitigate the size problems that CRLs suffer, CAs will be allowed to enter into CCADB a JSON array which contains a list of CRL URLs, which together form the equivalent of a full and complete CRL. This document aims to outline a design for a system which will generate and serve sharded CRLs in a scalable way.

## Requirements

Baseline Requirements:

* P0: All CRLs must have `nextUpdate` fields not more than 10 days after their `thisUpdate`.
* P0: All CRLs must be updated and reissued not more than 7 days after their `thisUpdate`.
* P0: All CRLs must contain a monotonically-increasing “CRL Number”
* P0: All entries in all CRLs must either:
* Specify a CRLReason reasonCode other than ‘unspecified’ or ‘certificateHold’; or
* (In the case that the official reason is ‘unspecified’) Not have a CRLReason at all.
* P0: CRL entries must not be removed until after the expiration of the corresponding certificate.
* P1: CRL URLs must have <10s of latency (no percentile specified).
* P1: CRL URLs must have 24x7 availability (no true SLO specified).
* P3: Subscriber certs are not required to embed the `crlDistributionPoint` URL.

Apple & Mozilla Requirements:

* P0: The CA must populate the “Full CRL URL” or the “JSON Array of CRL URLs” field in the “Pertaining to Certificates Issued by this CA” in CCADB.
* P0: When combined, the above CRLs must be the equivalent of a full and complete CRL.
* P1: All entries in all CRLs must, if they specify a reasonCode at all, specify exactly one of keyCompromise (1), affiliationChange(3), superseded (4), cessationOfOperation (5), or privilegeWithdrawn (9).
* P2: (Potentially) All CRLs must be updated and reissued not more than X hours after their `thisUpdate`.

Operational Requirements:

* P0: The design must co-exist with OCSP infrastructure for the near- to mid-term future.
* P0: The design must function in the event that we revoke 200M certificates in 24 hours.
* P1: The design should be flexible in long-term sharding methodology, to scale to 1B+ active certs.
* P1: CRL shards should not be more than 1GB in size.
* P1: The design should only vary in scale, not kind, in the face of exceptional revocation counts.
* P2: The design should host the CRLs outside of our datacenter.
* P2: The design should produce approximately-evenly-sized shards, even in exceptional circumstances.
* P2: The CRL number should match across all CRLs generated at the same time

Non-goals:

* The design should not have a different “mass revocation mode”; it should be designed and sized to handle a mass revocation of all of our certificates from the beginning
* The design is not intended to replace OCSP, only to exist alongside it
* The design does not need to support updating CRLs immediately after a certificate is revoked. The BRs only require that CRLs be updated every 7 days, and that revocation information be available in 24 hours (in the fastest case).

## Overview

We take inspiration from our current OCSP infrastructure and divide the system into four pieces:

1. Updating CRLs, responsible for knowing what the CRLs should look like and driving issuance
2. Generating CRLs, responsible for signing CRLs provided to it by the Updater
3. Storing CRLs, responsible for holding all current CRLs and any relevant metadata
4. Serving CRLs, responsible for ensuring relying parties have access to the CRLs

## Detailed Design

As noted in the overview, this design is broken into several components plus one overarching question, each of which we will examine individually. Within each section we will lay out our selected alternative; other options considered are at the end of this document.

### Updating CRLs

The CRL Updater will be a long-lived service which performs work on a periodic basis, much like today’s ocsp-updater. It will be written in Go, live in the Boulder repository, and be deployed on our datacenter infrastructure by our SREs. All of its communication with the database will be mediated via the SA.

The CRL updater will have a configuration value, the `period` at which it should work. The CRL Updater will also have a configured set of Issuers that it cares about.

Every `period`, the CRL updater will execute the following algorithm for each configured `Issuer`:

* Note the current time
  * Convert it to a string for use as the `thisUpdate` value
  * Convert it to an integer for use as the `CRL Number` extension
* Allocate a number of in-memory “buckets” equal to the configured number of CRL shards
* Query the SA (certificateStatus table) for the set of all certificates which are issued by the current Issuer, are not expired, and are revoked. For each certificate in the response stream:
  * If the certificate’s revokedAt timestamp is after the noted start time, discard it (it can be picked up by the next iteration). Otherwise:
  * Take the certificate’s serial number modulo the number of buckets
  * Add the certificate’s serial, revocation reason, and revocation time to the determined bucket
* For each bucket:
  * Stream the set of serials, reasons, and timestamps to the CA
  * Stream back the resulting CRL byte chunks
  * Store the resulting CRL shard

Potential optimizations here include:

* Setting the `period` such that we never need to generate CRLs “on the fly”. If we generate a whole new set every 6 hours, then we are always far ahead of both the BR requirements for CRL updates (every 7 days) and the BR requirements for revocation timelines (24 hours at the shortest).
* If holding the whole set of revoked certs in memory is too large, multiple crl-updaters can run, each responsible for only a subset of the shard buckets. Any certificate status they receive which does not fall into one of the buckets they are responsible for, they discard.
* If even that is too hard, the SA might be able to be convinced to do the serial-bucketing at query time, so that any given request only results in a stream of certs which fall into a subset of the buckets.

### Generating CRLs

For use by the CRL Updater, the CA will gain a new gRPC endpoint `GenerateCRL`. This method takes as its input a stream of arbitrarily many revoked certificates represented as (serial, revocationTime, revocationReason) triplets, as well as the IssuerNameID of the certificate which issued all of them. Because we want to guarantee that the CA will only ever sign well-formed x509 objects, and DER uses length-prefix encoding, we cannot simply compute a streaming hash of the incoming data – we unfortunately have to hold the whole set of entries in memory so that we can compute their length, add that length prefix, and then compute and sign a hash over the final structure. Despite using streams to transport large amounts of data, the API will be essentially synchronous. In order to avoid consuming too much memory on the CA, it will process the stream as it comes in, producing a stream of the DER bytes of the resulting CRL. So the CA will accept the incoming stream of entries, construct a full CRL, use the Go stdlib to ask the HSM to sign the object, and stream the resulting DER bytes back. It will emit an AUDIT log at the time it produces the signature.

This approach closely mirrors the approach for OCSP today, in which `GenerateOCSP` requests are identified by the (IssuerID, Serial) pair, and annotated by the (Reason, RevokedAt) metadata.

It is worth noting that this will be the first streaming gRPC method in Boulder. This may come with new operational surprises. But streaming appears to be a requirement because gRPC has a default maximum of 4MiB per message, and limiting our CRLs to that size would require maintaining an inordinately large number of CRL shards.

```proto
service CRLGenerator {
  rpc GenerateCRL(stream GenerateCRLRequest) returns (stream GenerateCRLResponse) {}
}

message GenerateCRLRequest {
  oneof payload {
    CRLMetadata metadata = 1;
    CRLEntry entry = 2;
  }
}

message CRLMetadata {
  int64 issuerNameID = 1;
  int64 thisUpdate = 2; // Unix timestamp (nanoseconds)
}

message CRLEntry {
  string serial = 1;
  int32 reason = 2;
  int64 revokedAt = 3; // Unix timestamp (nanoseconds)
}

message GenerateCRLResponse {
  bytes chunk = 1;
}
```

### Storing CRLs and Metadata

Storage is broken down into two kinds of storage -- metadata and binary CRL bytes data. Designs for both are presented below. In addition, the SA is expected to grow one new gRPC method to support the CRL Updater algorithm described above.

#### New SA Method

The SA will expose a new gRPC method which returns a stream of revoked certificates which can then be assorted into various CRL shards. Although the gRPC interface will be streaming, the internal implementation details need not be: this method could be implemented as a single SQL query, as a streaming SQL query, or even as multiple LIMITed SQL queries executed in succession.

The crlTimestamp in the request will be used both to filter out certificates which expired before that time and certificates which were revoked after that time.
 
```proto
service StorageAuthority {
  rpc GetRevokedCerts(GetRevokedCertsRequest) returns (stream RevokedCert) {}
}
 
message GetRevokedCertsRequest {
  int64 issuerNameID = 1;
  int64 crlTimestamp = 2;
}
 
message RevokedCert {
  string serial = 1;
  int32 reason = 2;
  int64 revokedAt = 3;
}
```

#### CRL Storage

Another long running service, the CRL Storage Manager, will sit between the crl-updater (which must have access to the SA and the CA) and our cloud storage (which requires access to the public internet). This service will live outside of the MFN. It will expose a simple gRPC interface.
 
```proto
service CRLStorage {
  rpc WriteCRL(stream CRLChunk) returns (goog.Empty) {}
}
 
message CRLChunk {
  int64 issuerNameID = 1;
  int64 shardID = 2;
  bytes chunk = 3;
}
```

As this service receives the stream of CRL chunks from the crl-updater, it will used S3’s chunked uploading to write the reconstituted file to an Amazon S3 bucket at a stable file path determined by the issuerNameID and the shardID, such as `/next/:issuerNameID/:shardID`. When it has uploaded all files for a given “generation” of CRL shards, it will atomically move all of the uploaded files to their permanent locations, such as `/:issuerNameID/:shardID`. This bucket will have versioning and object lifecycle management enabled, so that unexpected errors do not result in unrecoverable file corruption, and so that old versions are automatically pruned to keep cloud costs down.

It is worth noting that an upload of this size could experience interruptions and partial failures. The CRL Storage Manager should attempt to be resilient to transitory failures so that it is likely to succeed at uploading the whole batch and being able to move it into place. If a batch upload fails, monitoring should detect this and fire alarms.

In the future, we can optionally migrate to something like the upcoming Cloudflare R2 if it seems like that would be advantageous. Additionally, we can optionally have the CRL Storage Manager write the resulting files to multiple (preferably API-compatible) cloud storage providers, so that the responder can fail over to one of the alternatives in case of an outage.

#### Metadata Storage

No additional metadata storage is necessary for this design; all relevant data is already stored in the certificateStatus table.

### Serving CRLs

The responder is perhaps the biggest departure from our OCSP infrastructure. Rather than being a dynamic service which retrieves OCSP responses from the database (with a caching layer in front of it), the CRL Responder will simply be the direct public access provided by S3 natively.

We will use A records to point a short name (such as https://crl.lencr.org) at this S3 bucket, so that we can change the backing infrastructure without disrupting the list of URLs stored in CCADB, and so that we can theoretically fail over to a different cloud storage provider.

## Caveats

### Claiming CRL Shards are Not CRLs

There is one large semi-open question here: is it acceptable for a given revocation entry to move between CRL shards? The answer depends on whether you consider a CRL shard to be a standalone CRL. The BRs, Section 4.10.1, say “Revocation entries on a CRL… MUST NOT be removed until after the Expiry Date of the revoked Certificate.” If this requirement applies to each CRL shard individually, then we must have a binding between certs and shards that is stable for the lifetime of the certificate. If this requirement applies only to the “full and complete” CRL which is the union of all the individual shards, then it is acceptable to move revocation entries between shards.

Based on Mozilla’s and Apple's responses, we intend to move forward under the claim that it is acceptable for CRL entries to move between shards. We also believe that GoDaddy is currently issuing sharded CRLs in this way, and that no complaint has been lodged.

However, it is possible that some other root program or interested party will object to this practice.

### Changing the Number or URLs of CRL Shards

Although this design makes it easy to change the number of CRL shards being generated at any given time, that’s not the whole story. If we ever change the number of shards, we have to also change the list of URLs contained in CCADB. We expect this to be rare, so this design does not include a mechanism for automating this process.

However, as a manual process, some care must be taken when updating CCADB. For example, if we increase the number of shards from 90 to 180, we must ensure that there is not a period of time where the existing 90 shards contain only 50% of the data, and the new 90 shards are not yet listed in CCADB. Conversely, if we increase the number of shards from 90 to 180, we should ensure that there is not a period of time where 50% of the URLs listed in CCADB do not resolve.

### gRPC Streaming Methods

Multiple of the gRPC methods here need to facilitate the transfer of potentially-large CRL byte blobs. As such, multiple of the methods here are defined as gRPC streaming methods. These have not been used as part of Boulder before, and may present new and unexpected challenges. However, I believe that they are still our best path forward. The only two alternatives I see (using a transport mechanism other than gRPC, or requiring that all of our CRL shards be smaller than the gRPC message size limit) seem even less tenable.

### Incorporating New Infrastructure

This design requires incorporating new kinds of cloud infrastructure into Boulder’s daily operations. This is an area that we as a team want to be better at -- and we have some prior art both from Remote VAs and from Prio -- but it is still a risk to step outside our comfort zone in this way.
