package control

import (
	"path/filepath"
	"testing"
	"time"
)

// sync exchanges records both ways, the way a reconnecting pair does.
func syncPair(a, b *Store) (aAdopted, bAdopted int) {
	bAdopted = b.Merge(a.Missing(b.Digests()))
	aAdopted = a.Merge(b.Missing(a.Digests()))
	return
}

func TestStore_PutAndRead(t *testing.T) {
	s := testStore(t, "ns1")

	mustPut(t, s, KindSubscriber, "10.0.0.0/8", SubscriberRecord{Prefix: "10.0.0.0/8", ID: "acme", Class: "secure"})
	mustPut(t, s, KindClass, "secure", ClassRecord{Name: "secure", Action: "nxdomain"})

	if got := len(s.Records()); got != 2 {
		t.Fatalf("records = %d, want 2", got)
	}
	state, version := s.State()
	if subs, _, _, classes := state.Counts(); subs != 1 || classes != 1 {
		t.Errorf("state has %d subscribers and %d classes, want 1 and 1", subs, classes)
	}
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
}

// Writing to either node and syncing must leave both with the same records —
// that is the whole point of a shared control plane across the pair.
func TestStore_ConvergesFromEitherSide(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindSubscriber, "10.0.0.0/8", SubscriberRecord{Prefix: "10.0.0.0/8", ID: "acme", Class: "secure"})
	mustPut(t, ns2, KindClass, "secure", ClassRecord{Name: "secure", Action: "nxdomain"})

	syncPair(ns1, ns2)

	if ns1.Hash() != ns2.Hash() {
		t.Errorf("the pair did not converge:\n ns1 %s\n ns2 %s", ns1.Hash(), ns2.Hash())
	}
	if got := len(ns1.Records()); got != 2 {
		t.Errorf("ns1 holds %d records, want both", got)
	}
	if got := len(ns2.Records()); got != 2 {
		t.Errorf("ns2 holds %d records, want both", got)
	}
}

// A node written to while its peer was down must bring that peer up to date
// when it rejoins.
func TestStore_CatchesUpAfterOutage(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure"})
	syncPair(ns1, ns2)

	// ns2 is now "down": ns1 keeps taking writes.
	for _, p := range []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"} {
		mustPut(t, ns1, KindSubscriber, p, SubscriberRecord{Prefix: p, ID: "acme", Class: "secure"})
	}
	if _, err := ns1.Delete(KindClass, "secure"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// ns2 rejoins.
	_, adopted := syncPair(ns1, ns2)
	if adopted != 4 {
		t.Errorf("ns2 adopted %d records on rejoin, want 4", adopted)
	}
	if ns1.Hash() != ns2.Hash() {
		t.Error("the pair did not converge after catch-up")
	}
	// The delete must have travelled too.
	state, _ := ns2.State()
	if _, _, _, classes := state.Counts(); classes != 0 {
		t.Errorf("ns2 still holds %d classes; the delete did not replicate", classes)
	}
}

// Without tombstones a peer that was down during a delete resurrects the
// record when it syncs back, because from its side the record still exists.
func TestStore_DeleteIsNotResurrected(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindSubscriber, "10.0.0.0/8", SubscriberRecord{Prefix: "10.0.0.0/8", ID: "acme", Class: "secure"})
	syncPair(ns1, ns2)

	if _, err := ns1.Delete(KindSubscriber, "10.0.0.0/8"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	syncPair(ns1, ns2)

	for name, s := range map[string]*Store{"ns1": ns1, "ns2": ns2} {
		if got := len(s.Records()); got != 0 {
			t.Errorf("%s still serves %d records after the delete", name, got)
		}
	}

	// Syncing again must not bring it back.
	syncPair(ns1, ns2)
	if got := len(ns2.Records()); got != 0 {
		t.Errorf("the record was resurrected on ns2: %d records", got)
	}
}

// Conflicting edits to the same record during a link outage must converge on
// the same winner from both sides, deterministically.
func TestStore_ConflictConvergesDeterministically(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure", Action: "nxdomain"})
	syncPair(ns1, ns2)

	// The pair link drops; both sides edit the same record.
	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure", Action: "nodata"})
	mustPut(t, ns2, KindClass, "secure", ClassRecord{Name: "secure", Action: "redirect"})

	// Link returns.
	syncPair(ns1, ns2)
	syncPair(ns1, ns2)

	if ns1.Hash() != ns2.Hash() {
		t.Fatalf("conflicting edits did not converge:\n ns1 %s\n ns2 %s", ns1.Hash(), ns2.Hash())
	}

	// Both hold the same logical time, so the higher node ID breaks the tie
	// and ns2's edit is the survivor.
	state, _ := ns1.State()
	if got := state.Classes()[0].Action; got != "redirect" {
		t.Errorf("winner action = %q, want ns2's edit to win the tiebreak", got)
	}
}

// A later write must beat an earlier one regardless of which node made it.
func TestStore_LaterWriteWins(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure", Action: "nxdomain"})
	syncPair(ns1, ns2)

	// ns1 writes again, having seen ns2's logical time.
	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure", Action: "nodata"})
	syncPair(ns1, ns2)

	for name, s := range map[string]*Store{"ns1": ns1, "ns2": ns2} {
		state, _ := s.State()
		if got := state.Classes()[0].Action; got != "nodata" {
			t.Errorf("%s action = %q, want the later write", name, got)
		}
	}
}

// The hash is the drift detector that replaces consensus.
func TestStore_HashDetectsDrift(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	if ns1.Hash() != ns2.Hash() {
		t.Error("two empty stores should hash the same")
	}

	mustPut(t, ns1, KindClass, "secure", ClassRecord{Name: "secure"})
	if ns1.Hash() == ns2.Hash() {
		t.Error("a push that reached only one node must show as drift")
	}

	syncPair(ns1, ns2)
	if ns1.Hash() != ns2.Hash() {
		t.Error("hashes should match once the pair has synced")
	}
}

func TestStore_TombstoneCollection(t *testing.T) {
	s := testStore(t, "ns1")
	mustPut(t, s, KindClass, "secure", ClassRecord{Name: "secure"})
	if _, err := s.Delete(KindClass, "secure"); err != nil {
		t.Fatal(err)
	}

	if got := len(s.All()); got != 1 {
		t.Fatalf("tombstone count = %d, want 1", got)
	}
	if removed := s.CollectTombstones(time.Now()); removed != 0 {
		t.Errorf("collected %d fresh tombstones, want 0", removed)
	}
	if removed := s.CollectTombstones(time.Now().Add(TombstoneTTL + time.Hour)); removed != 1 {
		t.Errorf("collected %d expired tombstones, want 1", removed)
	}
	if got := len(s.All()); got != 0 {
		t.Errorf("records = %d after collection, want 0", got)
	}
}

func TestStore_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.json")

	s, err := Open(StoreOptions{NodeID: "ns1", Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mustPut(t, s, KindSubscriber, "10.0.0.0/8", SubscriberRecord{Prefix: "10.0.0.0/8", ID: "acme", Class: "secure"})
	mustPut(t, s, KindClass, "secure", ClassRecord{Name: "secure"})
	if _, err := s.Delete(KindClass, "secure"); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	before := s.Hash()

	reopened, err := Open(StoreOptions{NodeID: "ns1", Path: path})
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if reopened.Hash() != before {
		t.Errorf("hash changed across restart:\n before %s\n after  %s", before, reopened.Hash())
	}
	// The tombstone must survive, or a peer resurrects the record on rejoin.
	if got := len(reopened.All()); got != 2 {
		t.Errorf("records after restart = %d, want 2 including the tombstone", got)
	}

	// A write after restart must sort after everything already stored.
	r, err := reopened.Put(KindClass, "default", ClassRecord{Name: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Lamport <= 3 {
		t.Errorf("lamport = %d, want it to continue past the loaded records", r.Lamport)
	}
}

func TestStore_MissingComputesDelta(t *testing.T) {
	ns1 := testStore(t, "ns1")
	ns2 := testStore(t, "ns2")

	mustPut(t, ns1, KindClass, "a", ClassRecord{Name: "a"})
	mustPut(t, ns1, KindClass, "b", ClassRecord{Name: "b"})
	syncPair(ns1, ns2)

	mustPut(t, ns1, KindClass, "c", ClassRecord{Name: "c"})

	missing := ns1.Missing(ns2.Digests())
	if len(missing) != 1 {
		t.Fatalf("delta = %d records, want only the new one", len(missing))
	}
	if missing[0].Key != "c" {
		t.Errorf("delta contains %q, want c", missing[0].Key)
	}
}

func TestStore_RequiresNodeID(t *testing.T) {
	if _, err := Open(StoreOptions{}); err == nil {
		t.Error("a store without a node ID has no tiebreak and must be refused")
	}
}
