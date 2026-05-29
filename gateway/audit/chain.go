// Package-level hash chaining for audit events (D.4.a, tamper-evident audit).
//
// The idea, dal manuale Multifactor / Aegis: ogni linea di audit porta
// `prev_hash` (l'hash della linea precedente) e `hash` (sha256 di
// `prev_hash || canonical_json(event_with_hash_cleared)`). Modificare una riga
// gia' scritta richiede di riscrivere TUTTE le righe successive con i nuovi
// hash; senza la chiave di firma (D.4.b) chiunque puo' farlo, ma il VERIFIER
// se ne accorge perche' la nuova catena dovra' essere ricalcolata da zero e
// l'auditor vede che e' una catena diversa. Con la firma (D.4.b) anche
// quello diventa impossibile: la firma del vendor non e' falsificabile.
//
// Per ora D.4.a fornisce la catena e il verifier; D.4.b aggiungera' Ed25519
// sopra il `hash` di ogni evento e un endpoint/CLI che verifica le firme.
//
// Le funzioni qui dentro sono pure: niente I/O, niente stato globale. Il
// logger (logger.go) le usa serializzato sotto mutex. Il verifier
// (cmd/audit-verify) le usa offline su file `.jsonl`.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// GenesisHash e' il prev_hash della *primissima* riga di una catena. 64
// caratteri zero distinguono "primo evento" da "catena vuota" o "catena
// troncata", e fanno gia' bella figura agli occhi di un auditor che scorre
// gli artefatti senza spiegazione.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ComputeHash ritorna l'esadecimale dello sha256 di
// `prevHash || eventCanonical`. Pure: dati gli stessi input ritorna sempre
// lo stesso output, indipendentemente da quante volte sia chiamata.
//
// `eventCanonical` deve essere il JSON dell'event con `Hash` azzerato (il
// chiamante usa MarshalForHash che lo fa). PrevHash invece DEVE essere
// presente nei byte canonici (e' parte dell'evento, tipograficamente
// identica a ogni altro campo).
func ComputeHash(prevHash string, eventCanonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(eventCanonical)
	return hex.EncodeToString(h.Sum(nil))
}

// MarshalForHash serializza un Event per il calcolo dell'hash: clona l'event
// (per non mutare quello passato dal chiamante), azzera `Hash`, e marshala.
// L'output e' deterministico perche' `Event` non ha campi `map` (encoding/json
// serializza i field di struct in ordine di dichiarazione e gli slice in
// ordine d'inserimento). Se in futuro Event guadagna un `map[string]X` quel
// determinismo sparisce e ChainTest_DeterminismAcrossRuns lo intercetta
// (test in chain_test.go).
func MarshalForHash(e Event) ([]byte, error) {
	clone := e
	clone.Hash = ""
	return json.Marshal(clone)
}

// VerifyChain controlla che ogni evento abbia il PrevHash atteso e che il
// suo Hash sia esattamente `ComputeHash(prevHash, MarshalForHash(event))`.
// Cammina sequenzialmente; al primo errore ritorna (false, indice, motivo).
// Su successo: (true, -1, "").
//
// `startPrev` e' l'hash atteso del primissimo evento. Per una catena fresca
// passa GenesisHash; per verificare un segmento intermedio (es. la coda di
// un log file dopo un trim) passa l'hash buono che precede il segmento.
//
// Pure: nessuna scrittura, nessun side effect. Il verifier offline e il
// logger live possono chiamarla con la stessa garanzia.
func VerifyChain(events []Event, startPrev string) (bool, int, string) {
	prev := startPrev
	for i, ev := range events {
		if ev.PrevHash != prev {
			return false, i, fmt.Sprintf(
				"prev_hash mismatch at event %d (id=%s): expected %q, got %q",
				i, ev.EventID, prev, ev.PrevHash)
		}
		body, err := MarshalForHash(ev)
		if err != nil {
			return false, i, fmt.Sprintf("marshal failed at event %d (id=%s): %v", i, ev.EventID, err)
		}
		want := ComputeHash(ev.PrevHash, body)
		if want != ev.Hash {
			return false, i, fmt.Sprintf(
				"hash mismatch at event %d (id=%s): recomputed %q, line has %q",
				i, ev.EventID, want, ev.Hash)
		}
		prev = ev.Hash
	}
	return true, -1, ""
}
