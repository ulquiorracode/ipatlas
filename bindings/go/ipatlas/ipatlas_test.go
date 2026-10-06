package ipatlas_test

import (
	"net"
	"testing"

	"github.com/ulquiorracode/ipatlas/bindings/go/ipatlas"
)

func TestGoBinding(t *testing.T) {
	var db *ipatlas.Database
	var err error
	db, err = ipatlas.Open("../../../dist/ipatlas_goldsrc_city.bin")
	if err != nil {
		t.Fatalf("Required sample database failed to open: %v", err)
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
