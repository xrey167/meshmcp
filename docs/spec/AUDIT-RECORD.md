# meshmcp Audit Record & Checkpoint Specification — v0.1

Status: draft · Format owner: meshmcp · License: open (adopt freely)

This spec defines an interchange format for **tamper-evident, non-repudiable
audit of agent-to-tool activity**. Any gateway, proxy, or agent runtime can
emit it, and any party can verify it with only the signer's public key. The
goal is that "prove what the agents did" has one answer across tools, not one
per vendor.

## 1. Audit log

An audit log is a UTF-8 file of newline-delimited JSON objects (JSONL), one
**record** per line, in emission order. Each record commits to the previous
record's hash, forming a hash chain.

### 1.1 Record object

| Field | Type | Required | Meaning |
|---|---|---|---|
| `time` | string | yes | RFC 3339 timestamp (may be empty in test vectors). |
| `backend` | string | yes | Logical name of the tool/server the call targeted. |
| `peer` | string | yes | Caller identity (mesh FQDN, org id, or principal). |
| `peer_key` | string | no | Caller's cryptographic key (e.g. WireGuard public key). |
| `peer_addr` | string | no | Caller transport address. |
| `peer_spiffe_id` | string | no | Derived, additive SPIFFE identity label (`spiffe://<trust-domain>/peer/<key>`). A label only — enforcement keys on `peer_key`, never on this field. Present only when the emitter has a configured trust domain; see §1.4 for placement and mixed-fleet semantics. |
| `method` | string | yes | JSON-RPC method (`tools/call`, `enroll`, …). |
| `tool` | string | no | Tool name for `tools/call`. |
| `rpc_id` | string | no | JSON-RPC request id. |
| `decision` | string | yes | `allow` \| `deny` \| `cosign`. |
| `reason` | string | no | Human-readable justification. |
| `rule` | number | yes | Index of the matching policy rule, or `-1`. |
| `cost` | number | no | Cost/quota units this call consumed (F29); absent when zero. |
| `provenance` | array | no | Content refs (retrieved document / triple hashes) that produced the answer — a signed provenance receipt (F6). |
| `seq` | number | yes | 1-based monotonic sequence number. |
| `prev_hash` | string | yes | Hex SHA-256 of the previous record (`""` for `seq` 1). |
| `hash` | string | yes | Hex SHA-256 of this record (see 1.2). |

### 1.2 Record hash

Let `R` be the record object with `hash` set to the empty string (so, under
`omitempty`-style encoding, the `hash` key is absent) and all other fields —
including `seq` and `prev_hash` — populated. Serialize `R` to canonical JSON
(see 3), then:

```
hash = hex( SHA-256( canonical_json(R) ) )
```

`prev_hash` of record *n* MUST equal `hash` of record *n−1*; `prev_hash` of
record 1 is `""`.

### 1.3 Chain verification

A verifier reads records in order and, for each:

1. Assert `seq` equals the expected 1-based counter (detects insert/delete).
2. Assert `prev_hash` equals the previous record's `hash` (detects reorder).
3. Recompute `hash` per 1.2 from the record's content and assert it matches the
   stored `hash` (detects edit).

The first failing `seq` localizes the tampering. A hash chain is
**tamper-evident**: any edit, reorder, insertion, or deletion is detected
without the original — but an attacker who controls the whole file can rewrite
every record and re-link the chain. Signed checkpoints (§2) close that gap.

### 1.4 Additive fields & mixed-fleet compatibility (`peer_spiffe_id`)

`peer_spiffe_id` is an **additive, optional** field, appended after `hash` in
the canonical field order (§3) — never inserted before it. It is present only
when the emitter is configured with a SPIFFE trust domain (the gateway's
`trust_domain` setting for local records; a federation mapping's
`trust_domain` for boundary crossings) **and** the caller has a stable,
well-formed peer key; its value is `spiffe://<trust-domain>/peer/<key>`, where
`<key>` is the peer's public key re-encoded as unpadded URL-safe base64. It is
a label only: enforcement keys on `peer_key`, never on this field.

Compatibility semantics:

- **Records without the field are byte-identical to a pre-field build**
  (`omitempty` elides it), so existing logs, hashes, and chains verify
  unchanged. Leaving the trust domain unconfigured keeps emitting exactly
  yesterday's bytes.
- **Mixed-fleet note:** a record that DOES carry `peer_spiffe_id` hashes
  differently than the same logical record without it — the field is inside
  the hashed bytes like any other. An **old verifier** (one predating the
  field) that re-serializes records from a struct without it will therefore
  compute a different hash for such records and report a mismatch. This is
  expected, not tampering: upgrade verifiers before (or together with)
  enabling a trust domain on emitters. Verifiers that preserve unknown fields
  in canonical order, or same-version binaries, are unaffected.

Future additive fields MUST follow the same pattern: appended after `hash`
(and after previously appended additive fields), optional, `omitempty`.

## 2. Signed checkpoints

A checkpoint file is JSONL, one **checkpoint** per line, committing to a
contiguous run of records via a Merkle root and an Ed25519 signature.

### 2.1 Checkpoint object

| Field | Type | Meaning |
|---|---|---|
| `version` | number | `1`. |
| `checkpoint_seq` | number | 1-based checkpoint ordinal. |
| `from_seq` | number | First record `seq` covered. |
| `to_seq` | number | Last record `seq` covered. |
| `count` | number | Records covered (`to_seq − from_seq + 1`). |
| `merkle_root` | string | Hex Merkle root over covered records' hashes (§2.2). |
| `chain_head` | string | Hex `hash` of record `to_seq`. |
| `prev_checkpoint` | string | Hex hash of the previous checkpoint (§2.3), `""` for the first. |
| `time` | string | RFC 3339. |
| `pubkey` | string | Hex Ed25519 public key of the signer. |
| `signature` | string | Hex Ed25519 signature (§2.4). |

### 2.2 Merkle root

Leaves are the 32-byte record hashes (hex-decoded), in `seq` order. Using
RFC 6962-style domain separation:

```
leaf_hash(b)   = SHA-256( 0x00 || b )
node_hash(l,r) = SHA-256( 0x01 || l || r )
```

Combine pairwise up the tree; an odd node is promoted unchanged to the next
level. The root of an empty leaf set is `leaf_hash("")`.

### 2.3 Checkpoint hash

```
checkpoint_hash = hex( SHA-256( signing_bytes || signature_ascii ) )
```

where `signing_bytes` is defined in §2.4 and `signature_ascii` is the hex
`signature` string's bytes.

### 2.4 Signature

`signing_bytes` = canonical JSON of the checkpoint with `signature` set to `""`
(the `pubkey` field IS included, binding the signer to the payload).

```
signature = hex( Ed25519_sign( priv, signing_bytes ) )
```

### 2.5 Signed verification

Given the audit log, checkpoint file, and (optionally pinned) public key, a
verifier:

1. Recomputes every record's `hash` from content (§1.2), indexed by `seq`.
2. For each checkpoint in order:
   a. Verify the Ed25519 `signature`; if a key is pinned, assert `pubkey` matches.
   b. Assert `prev_checkpoint` equals the previous checkpoint's hash (§2.3).
   c. Assert `from_seq` == previous `to_seq` + 1 (no coverage gap).
   d. Recompute the Merkle root over records `[from_seq, to_seq]` and assert it
      equals `merkle_root`.
   e. Assert `chain_head` equals record `to_seq`'s recomputed hash.

Because the Merkle root is signed, an attacker who rewrites the file **and**
re-links the plain chain still cannot make step (d) pass without the private
key. The log is thus **non-repudiable and externally verifiable**.

### 2.6 Anchoring (optional)

A checkpoint MAY additionally be published to an independent witness (an
RFC 6962 transparency log, a notary, or a peer gateway). Anchoring defends
against an insider who controls both the file and the signing key: once a
checkpoint head is witnessed elsewhere, the log cannot be rolled back past it
without the witness disagreeing.

## 3. Canonical JSON

Records and checkpoints are serialized with: object keys in the field order
defined above (Go `encoding/json` struct order), no insignificant whitespace,
UTF-8, and standard JSON number/string encoding. Verifiers MUST re-serialize
using the same field order to reproduce hashes. (A future v0.2 may switch to a
sorted-key canonicalization such as JCS.)

## 4. Reference implementation

`meshmcp/policy` (`audit.go`, `chain.go`, `merkle.go`, `sign.go`,
`verify_signed.go`) and the `meshmcp audit verify` / `meshmcp audit keygen`
commands. A JSON Schema for the record is in `audit-record.schema.json`.
