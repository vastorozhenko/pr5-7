import argparse, base64, json, os, socket, ssl, sys, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import requests

HOST = os.environ.get('SERVER_HOST', '127.0.0.1')
TIMEOUT = 10


def base(args, https=True):
    return f'https://{args.host}:8443' if https else f'http://{args.host}:8080'


def verify(args):
    # --ca: перевірка сертифіката сервера за нашим CA; без --ca - за системними CA (самопідписаний не пройде)
    return args.ca if args.ca else True


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def show(r):
    print(r.status_code, r.text)


def info(msg):
    print(msg, file=sys.stderr)


# ----- echo -----

def echo(args):
    if args.http:
        show(requests.post(base(args, False) + '/echo-http', json={'msg': args.msg}, timeout=TIMEOUT))
    elif args.token:
        show(requests.post(base(args) + '/echo-https', json={'msg': args.msg}, headers=auth(args.token),
                           verify=verify(args), timeout=TIMEOUT))
    else:
        show(requests.post(base(args) + '/echo-http', json={'msg': args.msg}, verify=verify(args), timeout=TIMEOUT))


def tls_info(args):
    """Встановлює TLS-з'єднання з перевіркою CA та імені сервера і показує параметри handshake."""
    ctx = ssl.create_default_context(cafile=args.ca) if args.ca else ssl.create_default_context()
    with socket.create_connection((args.host, 8443), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.host) as s:
            cert = s.getpeercert()
            print('Server:      ', f'{args.host}:8443')
            print('TLS version: ', s.version())
            print('Cipher suite:', s.cipher()[0], f'({s.cipher()[2]} bit)')
            print('Subject:     ', dict(x[0] for x in cert['subject']))
            print('Issuer:      ', dict(x[0] for x in cert['issuer']))
            print('SAN:         ', ', '.join(f'{t}:{v}' for t, v in cert['subjectAltName']))
            print('Valid:       ', cert['notBefore'], '->', cert['notAfter'])
            print('Verification: OK (chain to CA and hostname checked)')


# ----- auth / JWT -----

def login(args):
    body = {'username': args.user, 'password': args.password}
    if getattr(args, 'otp', None):
        body['otp'] = args.otp
    r = requests.post(base(args) + '/auth/login', json=body, verify=verify(args), timeout=TIMEOUT)
    if r.status_code != 200:
        info(f'LOGIN FAIL {r.status_code} {r.text}')
        sys.exit(1)
    d = r.json()
    info(f'LOGIN OK: {args.user}, token expires in {d["expires_in"]} s')
    print(d['access_token'])


def get(path):
    def run(args):
        show(requests.get(base(args) + path, headers=auth(args.token), verify=verify(args), timeout=TIMEOUT))
    return run


def refresh(args):
    r = requests.post(base(args) + '/auth/refresh', headers=auth(args.token), verify=verify(args), timeout=TIMEOUT)
    if r.status_code != 200:
        info(f'REFRESH FAIL {r.status_code} {r.text}')
        sys.exit(1)
    info('REFRESH OK: old token revoked')
    print(r.json()['access_token'])


def logout(args):
    show(requests.post(base(args) + '/auth/logout', headers=auth(args.token), verify=verify(args), timeout=TIMEOUT))


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).rstrip(b'=').decode()


def forge(args):
    """Атаки на JWT: зміна ролі без нового підпису або алгоритм none."""
    h, p, s = args.token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
    payload['role'] = args.role
    if args.alg_none:
        print(f'{b64({"alg": "none", "typ": "JWT"})}.{b64(payload)}.')
    else:
        print(f'{h}.{b64(payload)}.{s}')


# ----- MFA -----

def mfa_setup(args):
    r = requests.post(base(args) + '/auth/mfa/setup', headers=auth(args.token), verify=verify(args), timeout=TIMEOUT)
    if r.status_code != 200:
        show(r)
        return
    d = r.json()
    print('Secret:', d['secret'])
    print('URI:   ', d['otpauth_uri'])
    try:
        import qrcode
        q = qrcode.QRCode(border=1)
        q.add_data(d['otpauth_uri'])
        q.print_ascii(invert=True)
    except ImportError:
        pass


def mfa_confirm(args):
    show(requests.post(base(args) + '/auth/mfa/confirm', json={'otp': args.otp}, headers=auth(args.token),
                       verify=verify(args), timeout=TIMEOUT))


def otp(args):
    """Генерує поточний код, як застосунок-автентифікатор."""
    import pyotp
    t = pyotp.TOTP(args.secret)
    print(t.now(), f'(valid for {30 - int(time.time()) % 30} s)')


# ----- атаки -----

def brute(args):
    for i in range(1, int(args.wrong) + 1):
        r = requests.post(base(args) + '/auth/login', json={'username': args.user, 'password': f'wrong{i}'},
                          verify=verify(args), timeout=TIMEOUT)
        extra = f' Retry-After={r.headers["Retry-After"]}' if 'Retry-After' in r.headers else ''
        print(f'attempt {i}: {r.status_code} {r.json()["detail"]}{extra}')
        if r.status_code == 429:
            break


def flood(args):
    def one(_):
        try:
            return requests.post(base(args) + '/echo-https', json={'msg': 'x'}, headers=auth(args.token),
                                 verify=verify(args), timeout=TIMEOUT).status_code
        except requests.RequestException:
            return 'error'
    t0 = time.perf_counter()
    with ThreadPoolExecutor(args.threads) as ex:
        codes = Counter(ex.map(one, range(args.n)))
    dt = time.perf_counter() - t0
    print(f'{args.n} requests in {dt:.2f} s ({args.n / dt:.0f} req/s), {args.threads} threads')
    for code, cnt in sorted(codes.items(), key=str):
        print(f'  HTTP {code}: {cnt}')


def main():
    ap = argparse.ArgumentParser(description='Secure Net App client')
    ap.add_argument('--host', default=HOST)
    sub = ap.add_subparsers(dest='cmd', required=True)

    def cmd(name, fn, ca=True):
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)
        if ca:
            p.add_argument('--ca')
        return p

    p = cmd('echo', echo); g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--http', action='store_true'); g.add_argument('--https', action='store_true')
    p.add_argument('--msg', required=True); p.add_argument('--token')
    cmd('tls-info', tls_info)
    for name in ('login', 'mfa-login'):
        p = cmd(name, login); p.add_argument('--user', required=True); p.add_argument('--password', required=True)
        p.add_argument('--otp', required=(name == 'mfa-login'))
    for name, path in (('whoami', '/whoami'), ('admin', '/admin/users')):
        p = cmd(name, get(path)); p.add_argument('--token', required=True)
    p = cmd('refresh', refresh); p.add_argument('--token', required=True)
    p = cmd('logout', logout); p.add_argument('--token', required=True)
    p = cmd('forge', forge, ca=False); p.add_argument('--token', required=True)
    p.add_argument('--role', default='admin'); p.add_argument('--alg-none', action='store_true')
    p = cmd('mfa-setup', mfa_setup); p.add_argument('--token', required=True)
    p = cmd('mfa-confirm', mfa_confirm); p.add_argument('--token', required=True); p.add_argument('--otp', required=True)
    p = cmd('otp', otp, ca=False); p.add_argument('--secret', required=True)
    p = cmd('brute', brute); p.add_argument('--user', required=True); p.add_argument('--wrong', type=int, default=20)
    p = cmd('flood', flood); p.add_argument('--token', required=True)
    p.add_argument('--n', type=int, default=100); p.add_argument('--threads', type=int, default=10)

    args = ap.parse_args()
    try:
        args.fn(args)
    except (requests.exceptions.SSLError, ssl.SSLError) as e:
        reason = 'certificate verify failed' if 'CERTIFICATE_VERIFY_FAILED' in str(e) else str(e)
        print(f'TLS ERROR: {reason}', file=sys.stderr)
        sys.exit(2)
    except (requests.exceptions.ConnectionError, OSError) as e:
        print(f'CONNECTION ERROR: {e}', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
