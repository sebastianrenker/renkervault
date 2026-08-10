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
  it('Alice und Bob leiten denselben initialen Sitzungsschlüssel her', () => {
    const { alice, bob } = establishSession();
    expect(alice.publicKey).toBeInstanceOf(Uint8Array);
    expect(bob.publicKey).toBeInstanceOf(Uint8Array);
  });

  it('volles X3DH (mit One-Time-Prekey) und lite X3DH liefern unterschiedliche Secrets', () => {
    const alice = makeParty();
    const bob = makeParty();
    const otpk = newX25519();

    const full = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey, otpk.pub);
    const lite = handshakeInitiator(alice.identity, bob.identity.pub, bob.prekey.pub, bob.pq.publicKey);
    expect(b64.enc(full.sk)).not.toBe(b64.enc(lite.sk));
  });
});

describe('Double Ratchet — Grundfluss', () => {
  it('Alice -> Bob -> Alice -> Bob', async () => {
    const { alice, bob } = establishSession();

    const m1 = await enc(alice, 'hallo bob');
    expect(await dec(bob, m1)).toBe('hallo bob');

    const m2 = await enc(bob, 'hallo alice');
    expect(await dec(alice, m2)).toBe('hallo alice');

    const m3 = await enc(alice, 'wie geht es dir');
    expect(await dec(bob, m3)).toBe('wie geht es dir');

    const m4 = await enc(bob, 'gut, danke');
    expect(await dec(alice, m4)).toBe('gut, danke');
  });

  it('1000 Nachrichten in Folge bleiben korrekt und die Sendekette bleibt in Sync', async () => {
    const { alice, bob } = establishSession();
    for (let i = 0; i < 1000; i++) {
      const msg = await enc(alice, `nachricht-${i}`);
      expect(await dec(bob, msg)).toBe(`nachricht-${i}`);
    }
  });

  it('abwechselnde Senderichtung über viele Runden bleibt korrekt', async () => {
    const { alice, bob } = establishSession();
    for (let i = 0; i < 200; i++) {
      const fromAlice = await enc(alice, `a${i}`);
      expect(await dec(bob, fromAlice)).toBe(`a${i}`);
      const fromBob = await enc(bob, `b${i}`);
      expect(await dec(alice, fromBob)).toBe(`b${i}`);
    }
  });
});

describe('Double Ratchet — Out-of-Order-Zustellung', () => {
  it('Zustellreihenfolge 1,4,2,3 wird korrekt entschlüsselt (skipped message keys)', async () => {
    const { alice, bob } = establishSession();
    const msgs = await Promise.all([1, 2, 3, 4].map((i) => enc(alice, `msg-${i}`)));

    expect(await dec(bob, msgs[0])).toBe('msg-1');
    expect(await dec(bob, msgs[3])).toBe('msg-4');
    expect(await dec(bob, msgs[1])).toBe('msg-2');
    expect(await dec(bob, msgs[2])).toBe('msg-3');
  });

  it('eine verlorene Nachricht (2 geht verloren) beeinträchtigt spätere Nachrichten nicht', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'eins');
    const m2 = await enc(alice, 'zwei'); // wird nie zugestellt
    const m3 = await enc(alice, 'drei');
    const m4 = await enc(alice, 'vier');
    void m2;

    expect(await dec(bob, m1)).toBe('eins');
    expect(await dec(bob, m3)).toBe('drei');
    expect(await dec(bob, m4)).toBe('vier');

    // Konversation danach funktioniert normal weiter
    const m5 = await enc(bob, 'antwort');
    expect(await dec(alice, m5)).toBe('antwort');
  });

  it('mehr als MAX_SKIP übersprungene Nachrichten werden abgelehnt, ohne den State zu zerstören', async () => {
    const { alice, bob } = establishSession();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 100; i++) msgs.push(await enc(alice, `m${i}`));

    // Nachricht 99 direkt zuzustellen überspringt 99 Slots > MAX_SKIP(64) -> muss ablehnen
    await expect(bob.decrypt(msgs[99])).rejects.toThrow();

    // Bobs State darf dabei nicht committet worden sein — eine normale, nicht
    // übersprungene Nachricht muss weiterhin funktionieren und (da es Bobs erste
    // erfolgreich entschlüsselte Nachricht ist) ihm eine eigene Sendekette geben.
    expect(await dec(bob, msgs[0])).toBe('m0');
    const reply = await enc(bob, 'ich lebe noch');
    expect(await dec(alice, reply)).toBe('ich lebe noch');

    // Hinweis: Alice hat 99 weitere Nachrichten aus der ALTEN Kette (1..99), die Bob nie
    // gesehen hat. Rattscht Alice danach erneut, trägt ihr pn diese 99 offenen Slots —
    // das übersteigt für Bob weiterhin MAX_SKIP und wird bewusst abgelehnt (inhärente,
    // dokumentierte Grenze des Skip-Key-Fensters, siehe SECURITY.md).
  });

  it('dokumentiert: bleibt ein Peer > MAX_SKIP hinter einer Kette zurück, bleibt ein späterer Ratchet dauerhaft unlesbar', async () => {
    const { alice, bob } = establishSession();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 100; i++) msgs.push(await enc(alice, `m${i}`));

    // Bob sieht nur die allererste Nachricht der Kette, die restlichen 99 nie.
    expect(await dec(bob, msgs[0])).toBe('m0');

    // Alice rattscht (z. B. weil sie auf Bobs Antwort reagiert) und sendet erneut —
    // ihr Header trägt pn=100 (Länge der alten, für Bob größtenteils unsichtbaren Kette).
    await dec(alice, await enc(bob, 'antwort'));
    const afterRatchet = await enc(alice, 'nach dem ratchet');

    // Das ist eine bewusste, dokumentierte Grenze des bounded-skip-Designs (wie bei
    // Signal): Bob kann die 99 fehlenden alten Slots nicht nachträglich aufholen.
    await expect(bob.decrypt(afterRatchet)).rejects.toThrow();
  });
});

describe('Double Ratchet — Replay- und Tamper-Schutz (P0-Regressionstest)', () => {
  it('eine wiederholt zugestellte (replayte) Nachricht wird beim zweiten Mal abgelehnt', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'original');
    expect(await dec(bob, m1)).toBe('original');

    await expect(bob.decrypt(m1)).rejects.toThrow();
  });

  it('Replay einer bereits verarbeiteten Nachricht korrumpiert NICHT den State für künftige Nachrichten', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'eins');
    const m2 = await enc(alice, 'zwei');
    expect(await dec(bob, m1)).toBe('eins');

    // Angreifer/fehlerhaftes Relay dupliziert m1 erneut, BEVOR m2 zugestellt wird
    await expect(bob.decrypt(m1)).rejects.toThrow();

    // m2 muss trotzdem normal entschlüsselbar sein
    expect(await dec(bob, m2)).toBe('zwei');
  });

  it('Replay eines bereits verwendeten skipped-message-key wird abgelehnt, ohne den Key doppelt zu verbrauchen', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'eins');
    const m2 = await enc(alice, 'zwei');
    const m3 = await enc(alice, 'drei');

    expect(await dec(bob, m3)).toBe('drei'); // 1 und 2 werden geskippt
    expect(await dec(bob, m1)).toBe('eins'); // konsumiert den geskippten key für n=0

    await expect(bob.decrypt(m1)).rejects.toThrow(); // erneuter Replay von m1 muss fehlschlagen

    // m2 (der andere geskippte key) muss weiterhin abrufbar sein
    expect(await dec(bob, m2)).toBe('zwei');
  });

  it('manipulierter Ciphertext wird abgelehnt und beschädigt die Ratchet-Kette nicht', async () => {
    const { alice, bob } = establishSession();
    const m1 = await enc(alice, 'echte nachricht');

    const tampered: RatchetMessage = { header: m1.header, ct: b64.enc(flipByte(b64.dec(m1.ct))) };
    await expect(bob.decrypt(tampered)).rejects.toThrow();

    // Die echte Nachricht muss danach immer noch entschlüsselbar sein —
    // der fehlgeschlagene Versuch darf den State nicht verändert haben.
    expect(await dec(bob, m1)).toBe('echte nachricht');
  });

  it('gefälschter Header mit beliebigem DH-Public-Key wird abgelehnt und zerstört die Sitzung nicht (P0)', async () => {
    const { alice, bob } = establishSession();
    const legit = await enc(alice, 'legitime nachricht 1');

    // Angreifer fälscht eine Nachricht mit frei gewähltem DH-Key im Header — das würde
    // vor dem Fix einen ungeprüften vollständigen DH-Ratchet-Schritt auslösen und Bobs
    // echten Sitzungsstand (inkl. seines eigenen neuen Ephemeral-Keys) zerstören.
    const forgedDh = newX25519();
    const forged: RatchetMessage = {
      header: { dh: b64.enc(forgedDh.pub), pn: 0, n: 0 },
      ct: b64.enc(new Uint8Array(32)),
    };
    await expect(bob.decrypt(forged)).rejects.toThrow();

    // Bobs Sitzung muss danach unverändert funktionieren
    expect(await dec(bob, legit)).toBe('legitime nachricht 1');
    const reply = await enc(bob, 'antwort von bob');
    expect(await dec(alice, reply)).toBe('antwort von bob');
  });

  it('mehrere aufeinanderfolgende Angriffsversuche verhindern nicht die weitere Kommunikation', async () => {
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

describe('Double Ratchet — Gleichzeitiges Senden / DH-Ratchet', () => {
  it('beide Seiten senden "gleichzeitig", bevor sie die jeweils neueste Nachricht der Gegenseite sehen', async () => {
    const { alice, bob } = establishSession();

    // Sitzung erst bidirektional aufbauen: Bob kann protokollbedingt erst senden,
    // nachdem er eine erste Nachricht von Alice erhalten (und damit CKs abgeleitet) hat.
    expect(await dec(bob, await enc(alice, 'init'))).toBe('init');
    expect(await dec(alice, await enc(bob, 'erste antwort'))).toBe('erste antwort');

    // Jetzt senden beide "gleichzeitig", jeweils ohne die neueste Nachricht der
    // Gegenseite gesehen zu haben (klassisches Double-Ratchet-Crossing-Szenario).
    const aliceMsg = await enc(alice, 'von alice, parallel');
    const bobMsg = await enc(bob, 'von bob, parallel');

    expect(await dec(bob, aliceMsg)).toBe('von alice, parallel');
    expect(await dec(alice, bobMsg)).toBe('von bob, parallel');

    // Konversation muss danach normal weiterlaufen (neue DH-Ratchets auf beiden Seiten)
    const follow1 = await enc(alice, 'weiter gehts');
    expect(await dec(bob, follow1)).toBe('weiter gehts');
    const follow2 = await enc(bob, 'ja klar');
    expect(await dec(alice, follow2)).toBe('ja klar');
  });

  it('DH-Ratchet-Schritt erzeugt neue Kettenschlüssel (Forward Secrecy zwischen Epochen)', async () => {
    const { alice, bob } = establishSession();
    const before = alice.publicKey.slice();

    const a1 = await enc(alice, 'a1');
    await dec(bob, a1); // Bob leitet jetzt seine eigene Sendekette ab
    const b1 = await enc(bob, 'b1'); // löst bei Alice beim Empfang einen DH-Ratchet aus
    await dec(alice, b1);

    expect(b64.enc(alice.publicKey)).not.toBe(b64.enc(before));
  });
});

describe('Double Ratchet — Session-Restore / Geräte-Neustart', () => {
  it('Sitzung überlebt Snapshot -> Neustart -> Restore ohne Nachrichtenverlust', async () => {
    const { alice, bob } = establishSession();
    await dec(bob, await enc(alice, 'vor dem neustart'));

    const bobSnapshot = bob.toSnapshot();
    const bobRestored = Ratchet.fromSnapshot(bobSnapshot);

    const afterRestart = await enc(alice, 'nach dem neustart');
    expect(await dec(bobRestored, afterRestart)).toBe('nach dem neustart');

    const reply = await enc(bobRestored, 'bob ist zurück');
    expect(await dec(alice, reply)).toBe('bob ist zurück');
  });

  it('restaurierte Sitzung verarbeitet weiterhin Out-of-Order-Nachrichten korrekt', async () => {
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

  it('Snapshot ist unabhängig von der Originalinstanz (keine gemeinsame Mutation)', async () => {
    const { alice, bob } = establishSession();
    const snap = bob.toSnapshot();
    const clone = Ratchet.fromSnapshot(snap);

    const m1 = await enc(alice, 'nur für original');
    await dec(bob, m1);

    // Der Klon, der vor dieser Nachricht erstellt wurde, darf durch das Entschlüsseln
    // im Original nicht verändert worden sein (kein Aliasing von Uint8Arrays/Maps).
    const snap2 = clone.toSnapshot();
    expect(snap2.nr).toBe(snap.nr);
  });
});

function flipByte(data: Uint8Array): Uint8Array {
  const copy = data.slice();
  copy[copy.length - 1] ^= 0xff;
  return copy;
}
