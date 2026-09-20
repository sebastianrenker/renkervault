# METADATA.md — Field-by-field metadata analysis of the envelope format

A complete breakdown of which field of the `Envelope` object
(`client/src/net/client.ts`) is visible to the relay operator and
which lies exclusively inside the end-to-end-encrypted
payload (`ct`). Extends [THREAT_MODEL.md](THREAT_MODEL.md) to the
field level, as required by the audit task, section 5.

**Basic principle:** everything except `ct` itself (and the fields
strictly required for the handshake, `x3dh`/`header`) is technically
visible plaintext JSON to the relay — there is currently NO additional
envelope-encryption layer beyond the raw payload.

| Field | Visible to relay? | Why / note |
|---|---|---|
| `ct` | ❌ No — this is the actual ciphertext | AES-256-GCM-encrypted, authenticated via the ratchet or group key |
| `chatId` | ✅ Yes | For groups: a random ID, no plaintext group name. For 1:1: identical to the account ID of the counterpart |
| `chatKind` | ✅ Yes | `direct`/`group` — reveals the communication pattern (1:1 vs. group) |
| `kind` | ✅ Yes | `text`/`file`/`edit`/`delete`/`reaction`/`presence`/`call-*` — the relay sees, e.g., that a call is being signaled, even without seeing audio/video content |
| `msgId` | ✅ Yes | A random ID per message, no plaintext content, but enables chaining edit/delete/reaction events to the original message |
| `ts` | ✅ Yes | Send timestamp — directly usable for timing correlation (see THREAT_MODEL.md, cover-traffic section) |
| `fromName` | ✅ Yes | **A deliberate trade-off, documented since SECURITY.md** — the sender's plaintext display name in the envelope, not in `ct`. It could in principle be moved into the encrypted payload, but was not changed for UI simplicity (the relay does not need to decrypt to render push previews and the like) |
| `fileName` / `fileSize` / `fileMime` | ✅ Yes | The file name and type are plaintext; the actual byte size is, since the padding update (section 4g in SECURITY.md), normalized to one of 9 buckets, no longer exactly proportional to the raw file — but `fileSize` as a *field* still transports the true original size as metadata |
| `expiresAt` | ✅ Yes | Expiry time for disappearing messages — indirectly reveals the retention period configured per chat |
| `replyTo` (`{id, fromName, preview}`) | ✅ Yes | **The quote preview text is in the plaintext of the envelope**, not in `ct` — the weakest point of the current metadata minimization. An attacker with relay visibility thereby sees text excerpts, even if they cannot decrypt the rest of the conversation |
| `forwardedFrom` | ✅ Yes | Name of the original source of a forwarded message, plaintext |
| `targetMsgId` | ✅ Yes | Reference ID for edit/delete/reaction, no content data |
| `emoji` / `reactionOp` | ✅ Yes | The reaction itself (e.g. 👍) currently travels as a plaintext field, not through `ct` |
| `presence` | ✅ Yes | Online/offline signal, plaintext (best-effort anyway, see SECURITY.md 3) |
| `header` (`{dh, pn, n}`) | ✅ Yes (mandatory) | The ratchet header must be readable by the recipient to decrypt at all — contains the public DH key and message counter, no secret values |
| `x3dh` (`{ephPub, identityPub, pqCt, otpkId}`) | ✅ Yes (mandatory, only on first contact) | Public handshake values, necessarily visible by construction for X3DH |
| `tag` | ✅ Yes, but deliberately NOT traceable to the account ID | A sealed-sender tag instead of the account ID from the second 1:1 message on (see SECURITY.md section 3a) |
| `from` (delivery meta field, set by the relay itself) | ✅ Yes on first contact, `null` for sealed-sender follow-up messages | Set server-side from the authenticated WebSocket connection, not transmitted by the client |

## Prioritized recommendation for further metadata minimization

Most valuable for a future hardening round, sorted by effort/benefit:

1. **Move `replyTo.preview` into the encrypted payload** —
   the largest plaintext-content leak in the current format, a comparatively
   small change (envelope field → part of the JSON that lands in `ct`).
2. **Move `fromName` into the payload** — analogous, but with the
   trade-off that the relay then cannot supply a display name for local push
   previews even on first delivery to a new device
   (not implemented anyway currently, so no real loss of function).
3. **Move `emoji`/`reactionOp` into the payload** — low
   benefit (short, generic values), but trivial to implement once
   1./2. are done (the same rebuild pattern).
4. **Move `fileName`, normalize `fileMime` generically** (e.g.
   always `application/octet-stream` in the plaintext field, the real type only in
   the payload) — prevents inferences like "the attachment is a
   `tax_return.pdf`" from relay logs alone.

Not sensibly minimizable without a fundamental architecture change:
`chatId`, `chatKind`, `ts`, `header`, `x3dh` — these are necessarily visible
by construction for routing or the protocol itself.
