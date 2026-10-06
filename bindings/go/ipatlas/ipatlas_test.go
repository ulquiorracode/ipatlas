package ipatlas_test

import (
	"net"
	"testing"

	"ipatlas"
)

func TestGoBinding(t *testing.T) {
	db, err := ipatlas.Open("../../../dist/ipatlas_goldsrc_city.bin")
	if err != nil {
		t.Skip("Sample database not found, skipping Go test")
		return
	}
	defer db.Close()

	ip := net.ParseIP("8.8.8.8")
	country, ok := db.LookupCountry(ip)
	if !ok || country != "US" {
		t.Fatalf("expected country US, got %s (ok=%v)", country, ok)
	}

	_ = db.IsThreat(ip)
	_ = db.IsDatacenter(ip)
}
