| Protocol | Connection | n | p50 (ms) | p95 (ms) | req/s |
|---|---|---:|---:|---:|---:|
| HTTP | new connection | 200 | 6.98 | 9.29 | 112 |
| HTTP | keep-alive | 200 | 4.48 | 5.86 | 219 |
| HTTPS | new connection | 200 | 11.26 | 14.73 | 86 |
| HTTPS | keep-alive | 200 | 4.74 | 5.93 | 208 |

Login (bcrypt cost 12 + JWT) over HTTPS: p50 = 242.8 ms (n=10)
