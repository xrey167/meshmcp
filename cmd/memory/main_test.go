package main

import (
	"path/filepath"
	"testing"

	"meshmcp/embed"
)

func newMem(t *testing.T) *memStore {
	t.Helper()
	m, err := openMemStore(filepath.Join(t.TempDir(), "m.jsonl"), embed.NewHashing(256))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return m
}

func TestMemoryWriteRecallProvenance(t *testing.T) {
	m := newMem(t)
	m.write("the deploy pipeline uses blue-green rollout", []string{"ops"}, "AGENT1")
	m.write("customer acme prefers email over phone", []string{"crm"}, "AGENT2")

	hits := m.search("how do we deploy", 3, "")
	if len(hits) == 0 || hits[0].Item.Peer != "AGENT1" {
		t.Fatalf("expected the ops memory (by AGENT1) on top, got %+v", hits)
	}

	// Tag-scoped recall returns only memories carrying that tag.
	crm := m.search("acme", 5, "crm")
	if len(crm) != 1 || crm[0].Item.Peer != "AGENT2" {
		t.Fatalf("crm-tag recall should return only the crm memory: %+v", crm)
	}
	ops := m.search("acme", 5, "ops")
	if len(ops) != 1 || !hasTag(ops[0].Item.Tags, "ops") {
		t.Fatalf("ops-tag recall should return only ops memories: %+v", ops)
	}
}

func TestMemoryRecentAndPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.jsonl")
	m, _ := openMemStore(path, embed.NewHashing(256))
	m.write("first", nil, "K")
	m.write("second", nil, "K")
	m.write("third", nil, "K")

	recent := m.recent(2)
	if len(recent) != 2 || recent[0].Text != "third" || recent[1].Text != "second" {
		t.Fatalf("recent order wrong: %+v", recent)
	}

	// Reload from disk.
	m2, err := openMemStore(path, embed.NewHashing(256))
	if err != nil {
		t.Fatal(err)
	}
	if m2.count() != 3 {
		t.Fatalf("reloaded count = %d, want 3", m2.count())
	}
}
