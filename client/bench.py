"""Порівняння HTTP і HTTPS: латентність p50/p95 і пропускна здатність.
Нове з'єднання на кожен запит (з handshake TLS) і повторне використання з'єднання (keep-alive)."""
import argparse, os, statistics, time
import requests

HOST = os.environ.get('SERVER_HOST', '127.0.0.1')


def measure(n, url, verify, session):
    s = requests.Session() if session else None
    lat = []
    t0 = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        r = (s or requests).post(url, json={'msg': 'x' * 64}, verify=verify, timeout=10)
        r.raise_for_status()
        lat.append((time.perf_counter() - t) * 1000)
    total = time.perf_counter() - t0
    return statistics.median(lat), statistics.quantiles(lat, n=20)[18], n / total


def measure_login(n, host, ca, user, password):
    lat = []
    for _ in range(n):
        t = time.perf_counter()
        r = requests.post(f'https://{host}:8443/auth/login', json={'username': user, 'password': password},
                          verify=ca, timeout=10)
        r.raise_for_status()
        lat.append((time.perf_counter() - t) * 1000)
    return statistics.median(lat)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=200)
    ap.add_argument('--ca', required=True)
    ap.add_argument('--host', default=HOST)
    ap.add_argument('--user')
    ap.add_argument('--password')
    ap.add_argument('--out', default='client/bench_results.md')
    a = ap.parse_args()

    rows = []
    for proto, url, verify in (('HTTP', f'http://{a.host}:8080/echo-http', True),
                               ('HTTPS', f'https://{a.host}:8443/echo-http', a.ca)):
        for session in (False, True):
            p50, p95, rps = measure(a.n, url, verify, session)
            mode = 'keep-alive' if session else 'new connection'
            rows.append(f'| {proto} | {mode} | {a.n} | {p50:.2f} | {p95:.2f} | {rps:.0f} |')
            print(f'{proto:<5} {mode:<15} n={a.n} p50={p50:.2f}ms p95={p95:.2f}ms {rps:.0f} req/s')
    lines = ['| Protocol | Connection | n | p50 (ms) | p95 (ms) | req/s |', '|---|---|---:|---:|---:|---:|'] + rows
    if a.user and a.password:
        p50 = measure_login(10, a.host, a.ca, a.user, a.password)
        print(f'Login (bcrypt cost 12 + JWT), HTTPS: n=10 p50={p50:.1f}ms')
        lines += ['', f'Login (bcrypt cost 12 + JWT) over HTTPS: p50 = {p50:.1f} ms (n=10)']
    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'Saved -> {a.out}')


if __name__ == '__main__':
    main()
