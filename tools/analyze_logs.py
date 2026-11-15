"""Аналіз JSON-журналу сервера: фільтри за типом події, часом, користувачем, IP, рівнем і кодом відповіді;
статистика подій, кодів 401/403/429 і найактивніших порушників."""
import argparse, json, re, sys, time
from collections import Counter

SUSPICIOUS = ('auth.fail', 'auth.lockout', 'auth.blocked', 'auth.token.invalid', 'auth.token.expired',
              'auth.token.missing', 'access.denied', 'rate.limit', 'mfa.confirm.fail', 'http.plaintext.blocked')


def parse_time(s):
    """ISO-час (2026-11-15T13:00:00) або відносний (30s, 10m, 2h)."""
    m = re.fullmatch(r'(\d+)([smh])', s)
    if m:
        sec = int(m.group(1)) * {'s': 1, 'm': 60, 'h': 3600}[m.group(2)]
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - sec))
    return s if s.endswith('Z') else s + 'Z'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='server/logs/app.jsonl')
    ap.add_argument('--event', help='тип події або префікс: auth, auth.fail, rate.limit, request ...')
    ap.add_argument('--user')
    ap.add_argument('--ip')
    ap.add_argument('--level', choices=['INFO', 'WARNING', 'ERROR'])
    ap.add_argument('--status', type=int)
    ap.add_argument('--since', help='ISO-час UTC або 30s/10m/2h')
    ap.add_argument('--until')
    ap.add_argument('--suspicious', action='store_true', help='лише підозрілі події')
    ap.add_argument('--list', action='store_true', help='вивести знайдені події')
    a = ap.parse_args()

    since = parse_time(a.since) if a.since else None
    until = parse_time(a.until) if a.until else None
    events = []
    with open(a.path, encoding='utf-8') as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if a.event and not (e['event'] == a.event or e['event'].startswith(a.event + '.')):
                continue
            if a.suspicious and not e['event'].startswith(SUSPICIOUS):
                continue
            if a.user and e.get('user') != a.user:
                continue
            if a.ip and e.get('ip') != a.ip:
                continue
            if a.level and e['level'] != a.level:
                continue
            if a.status and e.get('status') != a.status:
                continue
            if since and e['ts'] < since or until and e['ts'] > until:
                continue
            events.append(e)

    if a.list:
        for e in events:
            print(json.dumps(e, ensure_ascii=False))
        print()
    if not events:
        print('No events match the filter')
        return
    print(f'Events: {len(events)}  ({events[0]["ts"]} .. {events[-1]["ts"]})')
    print('By type:   ', dict(Counter(e['event'] for e in events).most_common()))
    codes = Counter(e['status'] for e in events if e['event'] == 'request' and e['status'] >= 400)
    if codes:
        print('HTTP errors:', dict(sorted(codes.items())))
    bad = [e for e in events if e['event'].startswith(SUSPICIOUS)]
    print('Suspicious:', len(bad))
    if bad:
        print('Top IPs:   ', Counter(e.get('ip') for e in bad).most_common(5))
        print('Top users: ', Counter(e.get('user') for e in bad if e.get('user')).most_common(5))


if __name__ == '__main__':
    sys.exit(main())
