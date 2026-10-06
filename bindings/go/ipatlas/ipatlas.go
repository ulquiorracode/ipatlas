// Package ipatlas provides a high-performance Go client for IPAtlas databases
// wrapping the native C-ABI shared library via cgo.
package ipatlas

/*
#cgo CFLAGS: -I${SRCDIR}/../../../adapters/ipatlas-adapter-c/include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lipatlas_adapter_c
#include "ipatlas.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"
)

// Database wraps an open IPAtlas database handle.
type Database struct {
	handle *C.IpAtlasHandle
}

// Open opens an IPAtlas binary database from a file path.
func Open(path string) (*Database, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.ipatlas_open(cPath)
	if handle == nil {
		return nil, errors.New("failed to open ipatlas database at: " + path)
	}
	return &Database{handle: handle}, nil
}

// OpenVerified opens and cryptographically verifies an IPAtlas database.
func OpenVerified(path string) (*Database, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.ipatlas_open_verified(cPath)
	if handle == nil {
		return nil, errors.New("failed to verify and open ipatlas database at: " + path)
	}
	return &Database{handle: handle}, nil
}

// Close closes and deallocates the database handle.
func (db *Database) Close() {
	if db.handle != nil {
		C.ipatlas_close(db.handle)
		db.handle = nil
	}
}

func ipToUint32(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, errors.New("only IPv4 is currently supported in C-ABI fast path")
	}
	return binary.BigEndian.Uint32(ipv4), nil
}

// LookupCountry returns the 2-letter ISO country code for an IP address.
func (db *Database) LookupCountry(ip net.IP) (string, bool) {
	if db.handle == nil {
		return "", false
	}
	ipU32, err := ipToUint32(ip)
	if err != nil {
		return "", false
	}

	var buf [4]C.char
	res := C.ipatlas_lookup_country_u32(db.handle, C.uint32_t(ipU32), &buf[0])
	if res == 1 {
		return C.GoString(&buf[0]), true
	}
	return "", false
}

// IsThreat returns true if the IP address is an identified threat (Proxy, VPN, Tor, Botnet, Spam).
func (db *Database) IsThreat(ip net.IP) bool {
	if db.handle == nil {
		return false
	}
	ipU32, err := ipToUint32(ip)
	if err != nil {
		return false
	}
	return C.ipatlas_is_threat_u32(db.handle, C.uint32_t(ipU32)) == 1
}

// IsDatacenter returns true if the IP address belongs to a cloud / hosting provider.
func (db *Database) IsDatacenter(ip net.IP) bool {
	if db.handle == nil {
		return false
	}
	ipU32, err := ipToUint32(ip)
	if err != nil {
		return false
	}
	return C.ipatlas_is_datacenter_u32(db.handle, C.uint32_t(ipU32)) == 1
}

// LookupFlags returns raw 32-bit threat and usage flags bitmask.
func (db *Database) LookupFlags(ip net.IP) (uint32, bool) {
	if db.handle == nil {
		return 0, false
	}
	ipU32, err := ipToUint32(ip)
	if err != nil {
		return 0, false
	}
	var flags C.uint32_t
	res := C.ipatlas_lookup_flags_u32(db.handle, C.uint32_t(ipU32), &flags)
	if res == 1 {
		return uint32(flags), true
	}
	return 0, false
}
