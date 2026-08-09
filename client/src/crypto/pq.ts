/**
 * Post-Quantum-Ergänzung des Schlüsselaustauschs (hybrid).
 * ==========================================================
 * ML-KEM-768 (FIPS 203, vormals "Kyber") aus @noble/post-quantum — vom
 * selben Autor/Auditstandard wie @noble/curves und @noble/hashes, die den
 * Rest der Kryptografie in diesem Projekt tragen.
 *
 * ⚠ TRANSPARENZ (siehe SECURITY.md): Dies schützt NUR den initialen
 * Schlüsselaustausch (X3DH-lite, einmal pro neuem Kontakt) gegen
 * "Harvest Now, Decrypt Later" durch einen künftigen kryptografisch
 * relevanten Quantencomputer — also gegen einen Angreifer, der heute
 * aufgezeichneten Datenverkehr erst in einigen Jahren mit einem
 * Quantencomputer entschlüsseln will. Die FORTLAUFENDEN Double-Ratchet-
 * Schritte (jede einzelne Nachricht danach) bleiben klassisch X25519-basiert
 * — exakt wie bei Signals PQXDH. Ein vollständig post-quantensicherer,
 * fortlaufender Ratchet ist derzeit aktives Forschungsgebiet (ML-KEM-
 * Chiffretexte sind mit >1 KB pro Schritt zu groß für einen Pro-Nachricht-
 * Ratchet) und daher hier bewusst nicht umgesetzt.
 *
 * Hybrid-Prinzip: Das finale Sitzungsgeheimnis kombiniert den klassischen
 * X25519-Diffie-Hellman-Wert MIT dem ML-KEM-Shared-Secret per HKDF. Damit
 * bleibt die Verbindung mindestens so sicher wie zuvor (rein X25519), selbst
 * wenn sich ML-KEM als fehlerhaft herausstellen sollte — und zusätzlich
 * quantensicher für die Handshake-Phase, falls X25519 künftig bricht.
 */
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export interface PqKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Neues ML-KEM-768-Schlüsselpaar erzeugen (Größen: sk 2400 B, pk 1184 B). */
export function newPqKeyPair(): PqKeyPair {
  const kp = ml_kem768.keygen();
  return { secretKey: kp.secretKey, publicKey: kp.publicKey };
}

/** Initiator-Seite: erzeugt Ciphertext + Shared Secret aus dem Public Key der Gegenseite. */
export function pqEncapsulate(theirPublicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  return ml_kem768.encapsulate(theirPublicKey);
}

/** Responder-Seite: gewinnt dasselbe Shared Secret aus dem Ciphertext zurück. */
export function pqDecapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
