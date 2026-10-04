# Migration V4 → V5

IPAtlas 0.5.0 introduced Generation V5 (dual-stack IPv4/IPv6, CRC32). V4 databases remain **readable** (`HeaderVariant::V4`), but flag bits were remapped. Recompile for full V5 semantics.

## Flag mapping (`GeoFlags::from_v4`)

| V4 bit | V4 meaning   | V5 maps to                  |
| ------ | ------------ | --------------------------- |
| 0x0001 | DCH          | `DCH` (1<<2)                |
| 0x0002 | ISP/RESIDENTIAL | `RESIDENTIAL` (1<<14)    |
| 0x0004 | MOB          | `MOBILE` (1<<12)            |
| 0x0008 | COM          | — dropped (no equivalent)   |
| 0x0010 | ORG          | — dropped                   |
| 0x0020 | GOV/MIL      | — dropped                   |
| 0x0040 | EDU/LIB      | — dropped                   |
| 0x0080 | CDN          | `CDN` (1<<13)               |
| 0x0100 | SPAM         | `SPAM` (1<<9)               |
| 0x0200 | SCANNER      | `SCANNER` (1<<10)           |
| 0x0400 | BOTNET       | `BOTNET` (1<<11)            |
| 0x0800 | PROXY        | `ANY_PROXY` + `VPN`         |

`COM/ORG/GOV/EDU` were generic enterprise tags with no V5 equivalent and read as `0` on V4 files. If you filter on them, recompile from source CSVs instead of relying on converted V4 lookups.

## V5 proxy types (new, from `proxy_type` column)

`VPN, TOR, DCH, PUB, WEB, SES, RES, CPN, EPN` + `ANY_PROXY` aggregator. `is_proxy()` matches any of them. V4 files only ever yield `VPN|ANY_PROXY` for old `0x0800`.

## Steps

1. Recompile: `ipatlas compile --mode full --geo DB.CSV --proxy PX.CSV -o new.bin` (add `--geo-v6/--proxy-v6` for IPv6).
2. Verify: `ipatlas info new.bin` → `version 5`, `crc32 OK`.
3. Spot-check flags on known proxy IPs before switching traffic.
