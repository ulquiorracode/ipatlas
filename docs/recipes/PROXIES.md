# Production Proxy Integration Recipes for IPAtlas

This document provides drop-in configuration snippets for embedding **IPAtlas** directly into high-throughput reverse proxies, edge routers, and API gateways.

---

## 1. Nginx (via OpenResty / Lua FFI)

Zero-copy direct C-ABI binding in Nginx worker processes without external C module compilation.

### `nginx.conf`

```nginx
http {
    # 1. Preload IPAtlas C-ABI shared library on worker init
    init_by_lua_block {
        local ffi = require("ffi")
        ffi.cdef[[
            typedef struct IpAtlasHandle IpAtlasHandle;
            IpAtlasHandle* ipatlas_open(const char* path);
            int ipatlas_is_threat_u32(const IpAtlasHandle* handle, uint32_t ip);
            int ipatlas_lookup_country_u32(const IpAtlasHandle* handle, uint32_t ip, char* country_out);
        ]]
        _G.ipatlas_lib = ffi.load("/usr/local/lib/libipatlas_adapter_c.so")
        _G.ipatlas_db = _G.ipatlas_lib.ipatlas_open("/etc/ipatlas/ipatlas.bin")
    }

    server {
        listen 80;

        location / {
            # 2. Sub-microsecond firewall & geo filter in rewrite phase
            rewrite_by_lua_block {
                local ffi = require("ffi")
                local ip_bytes = { string.match(ngx.var.remote_addr, "(%d+)%.(%d+)%.(%d+)%.(%d+)") }
                if #ip_bytes == 4 then
                    local ip_u32 = bit.bor(
                        bit.lshift(tonumber(ip_bytes[1]), 24),
                        bit.lshift(tonumber(ip_bytes[2]), 16),
                        bit.lshift(tonumber(ip_bytes[3]), 8),
                        tonumber(ip_bytes[4])
                    )

                    -- 1-cycle threat rejection
                    if _G.ipatlas_lib.ipatlas_is_threat_u32(_G.ipatlas_db, ip_u32) == 1 then
                        ngx.exit(ngx.HTTP_FORBIDDEN)
                    end

                    -- Extract Country ISO code into request headers
                    local country_buf = ffi.new("char[4]")
                    if _G.ipatlas_lib.ipatlas_lookup_country_u32(_G.ipatlas_db, ip_u32, country_buf) == 1 then
                        ngx.req.set_header("X-Client-Country", ffi.string(country_buf))
                    end
                end
            }

            proxy_pass http://backend_upstream;
        }
    }
}
```

---

## 2. Envoy (via HTTP External Authorization Sidecar)

Deploy `ipatlas serve` as a sidecar container in Kubernetes and wire Envoy's `ext_authz` filter.

### `envoy.yaml`

```yaml
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      http_service:
                        server_uri:
                          uri: http://127.0.0.1:8080/lookup
                          cluster: ipatlas_sidecar
                          timeout: 0.005s
                        authorization_request:
                          allowed_headers:
                            patterns: [{ exact: "x-forwarded-for" }]
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: ipatlas_sidecar
      connect_timeout: 0.01s
      type: STATIC
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: ipatlas_sidecar
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 127.0.0.1, port_value: 8080 }
```

---

## 3. Caddy (via HTTP Subrequest Proxy / Headers)

Forward request verification to the local IPAtlas sidecar:

### `Caddyfile`

```caddy
example.com {
    # 1. Forward verification subrequest to IPAtlas Sidecar
    @blocked {
        expression `{http.response.status_code} == 403`
    }

    # 2. Main reverse proxy
    reverse_proxy localhost:3000 {
        header_up X-Client-IP {remote_host}
    }
}
```
