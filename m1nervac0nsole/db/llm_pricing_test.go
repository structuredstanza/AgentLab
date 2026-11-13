package db

import "testing"

func TestProfilePricingRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	p := &LLMProfile{
		Name: "t-price-round-trip", Format: "openai", Model: "m", APIKey: "key",
		PriceInputPerM: 1.5, PriceOutputPerM: 4, PriceCacheReadPerM: 0.15, PriceCacheWritePerM: 0.3,
	}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })

	for name, load := range map[string]func() (*LLMProfile, error){
		"list": func() (*LLMProfile, error) {
			profiles, err := d.ListProfiles()
			if err != nil {
				return nil, err
			}
			for _, profile := range profiles {
				if profile.ID == id {
					return profile, nil
				}
			}
			return nil, nil
		},
		"by id": func() (*LLMProfile, error) { return d.ProfileByID(id) },
	} {
		stored, err := load()
		if err != nil || stored == nil {
			t.Fatalf("%s lookup: profile=%v err=%v", name, stored, err)
		}
		if stored.PriceInputPerM != p.PriceInputPerM || stored.PriceOutputPerM != p.PriceOutputPerM ||
			stored.PriceCacheReadPerM != p.PriceCacheReadPerM || stored.PriceCacheWritePerM != p.PriceCacheWritePerM {
			t.Errorf("%s pricing = (%v, %v, %v, %v), want (%v, %v, %v, %v)", name,
				stored.PriceInputPerM, stored.PriceOutputPerM, stored.PriceCacheReadPerM, stored.PriceCacheWritePerM,
				p.PriceInputPerM, p.PriceOutputPerM, p.PriceCacheReadPerM, p.PriceCacheWritePerM)
		}
	}
}
