package postgres

import (
	"context"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestBGPInstance_UpsertGet(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	repo := db.BGPInstances()

	got, err := repo.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("Get on empty table = %+v; want nil", got)
	}

	first := &store.BGPInstance{
		LocalASN:    4294967295,
		RouterID:    "192.0.2.1",
		ListenPort:  179,
		RTBHNextHop: "203.0.113.1",
	}
	if err := repo.Upsert(ctx, first); err != nil {
		t.Fatal(err)
	}
	got, err = repo.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("Get after Upsert = nil")
	}
	if got.LocalASN != first.LocalASN || got.RouterID != first.RouterID ||
		got.ListenPort != first.ListenPort || got.RTBHNextHop != first.RTBHNextHop {
		t.Fatalf("roundtrip = %+v; want %+v", got, first)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero")
	}

	second := &store.BGPInstance{
		LocalASN:    65000,
		RouterID:    first.RouterID,
		ListenPort:  0,
		RTBHNextHop: "",
	}
	if err := repo.Upsert(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err = repo.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("Get after second Upsert = nil")
	}
	if got.LocalASN != second.LocalASN || got.RouterID != second.RouterID ||
		got.ListenPort != second.ListenPort || got.RTBHNextHop != second.RTBHNextHop {
		t.Fatalf("second roundtrip = %+v; want %+v", got, second)
	}

	var count int
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM bgp_instance`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("bgp_instance rows = %d; want 1", count)
	}
}

func TestBGPConnector_NeighborColumnsRoundTrip(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	repo := db.BGPConnectors()

	conn := &store.BGPConnector{
		Name:          "dao15a-neighbor",
		BGPASN:        64512,
		AddressFamily: "auto",
		Enabled:       true,
		Vendor:        "mikrotik",
		NeighborIP:    "198.51.100.1",
		NeighborASN:   4294967295,
		MD5Password:   "s3cret",
	}
	id, err := repo.Create(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repo.Delete(context.Background(), id); err != nil {
			t.Errorf("cleanup connector %d: %v", id, err)
		}
	})

	got, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.NeighborIP != conn.NeighborIP || got.NeighborASN != conn.NeighborASN ||
		got.MD5Password != conn.MD5Password || got.Vendor != conn.Vendor {
		t.Fatalf("created connector = %+v; want neighbor fields from %+v", got, conn)
	}

	got.NeighborASN = 65010
	got.MD5Password = ""
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if updated.NeighborASN != 65010 || updated.MD5Password != "" {
		t.Fatalf("updated connector = %+v; want neighbor_asn=65010 md5_password=''", updated)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range list {
		if row.ID == id {
			found = true
			if row.NeighborIP != "198.51.100.1" || row.NeighborASN != 65010 {
				t.Fatalf("listed connector = %+v; want neighbor fields from update", row)
			}
		}
	}
	if !found {
		t.Fatalf("List did not include connector %d", id)
	}
}
