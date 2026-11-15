package db

import (
	"context"
	"testing"
)

func TestToolManifestStoreRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	const id = "dbtest-manifest"
	t.Cleanup(func() { _, _ = d.DeleteToolManifest(ctx, id) })

	if err := d.UpsertToolManifest(ctx, id, "one"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertToolManifest(ctx, id, "two"); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListToolManifests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *ToolManifestRow
	for i := range rows {
		if rows[i].ID == id {
			found = &rows[i]
		}
	}
	if found == nil || found.TOML != "two" {
		t.Fatalf("upsert did not replace the stored text: %+v", found)
	}
	if ok, err := d.DeleteToolManifest(ctx, id); err != nil || !ok {
		t.Fatalf("delete = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := d.DeleteToolManifest(ctx, id); err != nil || ok {
		t.Fatalf("second delete = (%v, %v), want (false, nil)", ok, err)
	}
}
