import { describe, it, expect } from 'vitest';
import { newX25519, utf8, b64 } from '../../src/crypto/primitives';
import { newPqKeyPair } from '../../src/crypto/pq';
import {
  Ratchet, RatchetMessage, handshakeInitiator, handshakeResponder,
} from '../../src/crypto/ratchet';

interface Party {
  identity: ReturnType<typeof newX25519>;
  prekey: ReturnType<typeof newX25519>;
  pq: ReturnType<typeof newPqKeyPair>;
}

function makeParty(): Party {
  return { identity: newX25519(), prekey: newX25519(), pq: newPqKeyPair() };
}

function establishSession(): { alice: Ratchet; bob: Ratchet } {
  const alice = makeParty();
  const bob = makeParty();

  const { sk: aliceSk, ephPub, pqCipherText } = handshakeInitiator(
    alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey
  );
  const bobSk = handshakeResponder(
    bob.identity, bob.prekey, alice.identity.pub, ephPub, bob.pq.secretKey, pqCipherText
  );
  expect(b64.enc(aliceSk)).toBe(b64.enc(bobSk));

  const aliceRatchet = Ratchet.initAlice(aliceSk, bob.prekey.pub);
  const bobRatchet = Ratchet.initBob(bobSk, bob.prekey);
  return { alice: aliceRatchet, bob: bobRatchet };
}

async function enc(r: Ratchet, text: string): Promise<RatchetMessage> {
  return r.encrypt(utf8.enc(text));
}
async function dec(r: Ratchet, m: RatchetMessage): Promise<string> {
  return utf8.dec(await r.decrypt(m));
}

describe('Double Ratchet — X3DH-PQ-Hybrid handshake', () => {
  it('Alice and Bob derive the same initial session key', () => {
    const { alice, bob } = establishSession();
    expect(alice.publicKey).toBeInstanceOf(Uint8Array);
    expect(bob.publicKey).toBeInstanceOf(Uint8Array);
  });

  it('full X3DH (with a one-time prekey) and lite X3DH yield different secrets', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otpk = newX25519();

    const full = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, otpk.pub);
    const lite = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(full.sk)).not.toBe(b64.enc(lite.sk));
  });
});

describe('Double Ratchet — basic flow', () => {
  it('Alice -> Bob -> Alice -> Bob', async () => {
    const { alice, bob } = establishSession();

    const m1 = await enc(alice, 'hello bob');
    expect(await dec(bob, m1)).toBe('hello bob');

    const m2 = await enc(bob, 'hello alice');
    expect(await dec(alice, m2)).toBe('hello alice');

    const m3 = await enc(alice, 'how are you');
    expect(await dec(bob, m3)).toBe('how are you');

    const m4 = await enc(bob, 'good, thanks');
    expect(await dec(alice, m4)).toBe('good, thanks');
  });

  it('1000 messages in a row stay correct and the sending chain stays in sync', async () => {
    const { alice, bob } = establishSession();
    for (let i = 0; i < 1000; i++) {
      const msg = await enc(alice, `message-${i}`);
      expect(await dec(bob, msg)).toBe(`message-${i}`);
    }
  });

  it('alternating send direction stays correct over many rounds', async () => {
    const { alice, bob } = establishSession();
    for (let i = 0; i < 200; i++) {
      const fromAlice = await enc(alice, `a${i}`);
      expect(await dec(bob, fromAlice)).toBe(`a${i}`);
      const fromBob = await enc(bob, `b${i}`);
      expect(await dec(alice, fromBob)).toBe(`b${i}`);
    }
  });
});

describe('Double Ratchet — out-of-order delivery', () => {
  it('delivery order 1,4,2,3 is decrypted correctly (skipped message keys)', async () => {
    const { alice, bob } = establishSession();
    const msgs = await Promise.all([1, 2, 3, 4].map((i) => enc(alice, `msg-${i}`)));

    expect(await dec(bob, msgs[0])).toBe('msg-1');
    expect(await dec(bob, msgs[3])).toBe('msg-4');
    expect(await dec(bob, msgs[1])).toBe('msg-2');
    expect(await dec(bob, msgs[2])).toBe('msg-3');
  });

  it('a lost message (2 is lost) does not affect later messages', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'one');
    const m2 = await enc(alice, 'two'); // is never delivered
    const m3 = await enc(alice, 'three');
    const m4 = await enc(alice, 'four');
    void m2;

    expect(await dec(bob, m1)).toBe('one');
    expect(await dec(bob, m3)).toBe('three');
    expect(await dec(bob, m4)).toBe('four');

    // The conversation continues normally afterwards
    const m5 = await enc(bob, 'reply');
    expect(await dec(alice, m5)).toBe('reply');
  });

  it('more than MAX_SKIP skipped messages are rejected without destroying the state', async () => {
    const { alice, bob } = establishSession();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 100; i++) msgs.push(await enc(alice, `m${i}`));

    // Delivering message 99 directly skips 99 slots > MAX_SKIP(64) -> must reject
    await expect(bob.decrypt(msgs[99])).rejects.toThrow();

    // Bob's state must not have been committed here — a normal, non-skipped
    // message must still work and (since it is Bob's first successfully
    // decrypted message) give him his own sending chain.
    expect(await dec(bob, msgs[0])).toBe('m0');
    const reply = await enc(bob, 'still alive');
    expect(await dec(alice, reply)).toBe('still alive');

    // Note: Alice has 99 more messages from the OLD chain (1..99) that Bob never
    // saw. If Alice then ratchets again, her pn carries these 99 open slots —
    // that still exceeds MAX_SKIP for Bob and is deliberately rejected (an inherent,
    // documented limit of the skip-key window, see SECURITY.md).
  });

  it('documented: if a peer stays > MAX_SKIP behind a chain, a later ratchet stays permanently unreadable', async () => {
    const { alice, bob } = establishSession();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 100; i++) msgs.push(await enc(alice, `m${i}`));

    // Bob sees only the very first message of the chain, never the remaining 99.
    expect(await dec(bob, msgs[0])).toBe('m0');

    // Alice ratchets (e.g. because she reacts to Bob's reply) and sends again —
    // her header carries pn=100 (length of the old chain, mostly invisible to Bob).
    await dec(alice, await enc(bob, 'reply'));
    const afterRatchet = await enc(alice, 'after the ratchet');

    // This is a deliberate, documented limit of the bounded-skip design (as with
    // Signal): Bob cannot catch up on the 99 missing old slots afterwards.
    await expect(bob.decrypt(afterRatchet)).rejects.toThrow();
  });
});

describe('Double Ratchet — replay and tamper protection (P0 regression test)', () => {
  it('a repeatedly delivered (replayed) message is rejected the second time', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'original');
    expect(await dec(bob, m1)).toBe('original');

    await expect(bob.decrypt(m1)).rejects.toThrow();
  });

  it('replaying an already-processed message does NOT corrupt the state for future messages', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'one');
    const m2 = await enc(alice, 'two');
    expect(await dec(bob, m1)).toBe('one');

    // An attacker/faulty relay duplicates m1 again BEFORE m2 is delivered
    await expect(bob.decrypt(m1)).rejects.toThrow();

    // m2 must still be decryptable normally
    expect(await dec(bob, m2)).toBe('two');
  });

  it('replaying an already-used skipped-message key is rejected without consuming the key twice', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'one');
    const m2 = await enc(alice, 'two');
    const m3 = await enc(alice, 'three');

    expect(await dec(bob, m3)).toBe('three'); // 1 and 2 are skipped
    expect(await dec(bob, m1)).toBe('one'); // consumes the skipped key for n=0

    await expect(bob.decrypt(m1)).rejects.toThrow(); // replaying m1 again must fail

    // m2 (the other skipped key) must still be retrievable
    expect(await dec(bob, m2)).toBe('two');
  });

  it('tampered ciphertext is rejected and does not damage the ratchet chain', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'real message');

    const tampered: RatchetMessage = { header: m1.header, ct: b64.enc(flipByte(b64.dec(m1.ct))) };
    await expect(bob.decrypt(tampered)).rejects.toThrow();

    // The real message must still be decryptable afterwards —
    // the failed attempt must not have changed the state.
    expect(await dec(bob, m1)).toBe('real message');
  });

  it('a forged header with an arbitrary DH public key is rejected and does not destroy the session (P0)', async () => {
    const { alice, bob } = establishSession();
    const legit = await enc(alice, 'legit message 1');

    // An attacker forges a message with a freely chosen DH key in the header — before
    // the fix this would trigger an unchecked full DH ratchet step and destroy Bob's
    // real session state (incl. his own new ephemeral key).
    const forgedDh = newX25519();
    const forged: RatchetMessage = {
      header: { dh: b64.enc(forgedDh.pub), pn: 0, n: 0 },
      ct: b64.enc(new Uint8Array(32)),
    };
    await expect(bob.decrypt(forged)).rejects.toThrow();

    // Bob's session must still work unchanged afterwards
    expect(await dec(bob, legit)).toBe('legit message 1');
    const reply = await enc(bob, 'reply from bob');
    expect(await dec(alice, reply)).toBe('reply from bob');
  });

  it('several consecutive attack attempts do not prevent further communication', async () => {
    const { alice, bob } = establishSession();
    const legit1 = await enc(alice, 'ok-1');
    expect(await dec(bob, legit1)).toBe('ok-1');

    for (let i = 0; i < 10; i++) {
      const junk: RatchetMessage = {
        header: { dh: legit1.header.dh, pn: 0, n: 999 + i },
        ct: b64.enc(new Uint8Array(32)),
      };
      await expect(bob.decrypt(junk)).rejects.toThrow();
    }

    const legit2 = await enc(alice, 'ok-2');
    expect(await dec(bob, legit2)).toBe('ok-2');
  });
});

describe('Double Ratchet — simultaneous send / DH ratchet', () => {
  it('both sides send "simultaneously" before they see each other\'s latest message', async () => {
    const { alice, bob } = establishSession();

    // First build the session bidirectionally: by protocol Bob can only send
    // after he has received a first message from Alice (and thus derived CKs).
    expect(await dec(bob, await enc(alice, 'init'))).toBe('init');
    expect(await dec(alice, await enc(bob, 'first reply'))).toBe('first reply');

    // Now both send "simultaneously", each without having seen the other side's
    // latest message (the classic Double Ratchet crossing scenario).
    const aliceMsg = await enc(alice, 'from alice, parallel');
    const bobMsg = await enc(bob, 'from bob, parallel');

    expect(await dec(bob, aliceMsg)).toBe('from alice, parallel');
    expect(await dec(alice, bobMsg)).toBe('from bob, parallel');

    // The conversation must continue normally afterwards (new DH ratchets on both sides)
    const follow1 = await enc(alice, 'keep going');
    expect(await dec(bob, follow1)).toBe('keep going');
    const follow2 = await enc(bob, 'sure');
    expect(await dec(alice, follow2)).toBe('sure');
  });

  it('a DH ratchet step produces new chain keys (forward secrecy between epochs)', async () => {
    const { alice, bob } = establishSession();
    const before = alice.publicKey.slice();

    const a1 = await enc(alice, 'a1');
    await dec(bob, a1); // Bob now derives his own sending chain
    const b1 = await enc(bob, 'b1'); // triggers a DH ratchet at Alice on receipt
    await dec(alice, b1);

    expect(b64.enc(alice.publicKey)).not.toBe(b64.enc(before));
  });
});

describe('Double Ratchet — session restore / device restart', () => {
  it('the session survives snapshot -> restart -> restore without message loss', async () => {
    const { alice, bob } = establishSession();
    await dec(bob, await enc(alice, 'before restart'));

    const bobSnapshot = bob.toSnapshot();
    const bobRestored = Ratchet.fromSnapshot(bobSnapshot);

    const afterRestart = await enc(alice, 'after restart');
    expect(await dec(bobRestored, afterRestart)).toBe('after restart');

    const reply = await enc(bobRestored, 'bob is back');
    expect(await dec(alice, reply)).toBe('bob is back');
  });

  it('a restored session still processes out-of-order messages correctly', async () => {
    const { alice, bob } = establishSession();
    await dec(bob, await enc(alice, 'init'));

    const restored = Ratchet.fromSnapshot(bob.toSnapshot());
    const m1 = await enc(alice, 'x1');
    const m2 = await enc(alice, 'x2');
    const m3 = await enc(alice, 'x3');

    expect(await dec(restored, m3)).toBe('x3');
    expect(await dec(restored, m1)).toBe('x1');
    expect(await dec(restored, m2)).toBe('x2');
  });

  it('a snapshot is independent of the original instance (no shared mutation)', async () => {
    const { alice, bob } = establishSession();
    const snap = bob.toSnapshot();
    const clone = Ratchet.fromSnapshot(snap);

    const m1 = await enc(alice, 'only for the original');
    await dec(bob, m1);

    // The clone created before this message must not have been changed by decrypting
    // in the original (no aliasing of Uint8Arrays/Maps).
    const snap2 = clone.toSnapshot();
    expect(snap2.nr).toBe(snap.nr);
  });
});

function flipByte(data: Uint8Array): Uint8Array {
  const copy = data.slice();
  copy[copy.length - 1] ^= 0xff;
  return copy;
}
