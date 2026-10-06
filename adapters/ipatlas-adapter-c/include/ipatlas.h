#ifndef IPATLAS_H
#define IPATLAS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque database handle pointer.
 */
typedef struct IpAtlasHandle IpAtlasHandle;

/**
 * Opens an IPAtlas binary database from a null-terminated file path.
 * Returns NULL if opening or verification fails.
 */
IpAtlasHandle* ipatlas_open(const char* path);

/**
 * Closes and frees an IPAtlas database handle.
 */
void ipatlas_close(IpAtlasHandle* handle);

/**
 * Look up raw threat flags bitmask for an IPv4 address (host byte order integer).
 * Returns 0 if not found.
 */
uint32_t ipatlas_lookup_flags_u32(const IpAtlasHandle* handle, uint32_t ip);

/**
 * Fast threat predicate: returns 1 if known threat (Proxy, VPN, Tor, Botnet, Spam), 0 otherwise.
 */
int ipatlas_is_threat_u32(const IpAtlasHandle* handle, uint32_t ip);

/**
 * Fast datacenter predicate: returns 1 if datacenter / hosting IP, 0 otherwise.
 */
int ipatlas_is_datacenter_u32(const IpAtlasHandle* handle, uint32_t ip);

/**
 * Look up 2-letter ISO country code into a user-provided buffer of at least 3 bytes.
 * Returns 1 on success (writing null-terminated string), 0 on not found.
 */
int ipatlas_lookup_country_u32(const IpAtlasHandle* handle, uint32_t ip, char* country_out);

#ifdef __cplusplus
}
#endif

#endif /* IPATLAS_H */
