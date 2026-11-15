import time
import jwt, pyotp
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from server.models import EchoIn, LoginIn, OtpIn, TokenOut
from server import security as sec
from server.ratelimit import RateLimiter
from server.logger_setup import get_logger

app = FastAPI(title='Secure Net App', docs_url=None, redoc_url=None, openapi_url=None)
logger = get_logger()
rl = RateLimiter()

PLAIN_ALLOWED = {'/health', '/echo-http'}      # що доступно без TLS (порт 8080)
NO_RATE_LIMIT = {'/health', '/echo-http'}       # базовий ехо-ендпоінт для порівняння HTTP і HTTPS


def log(level, event, **fields):
    logger.log(level, event, extra={'extra': fields})


def client_ip(req: Request) -> str:
    return req.client.host if req.client else 'unknown'


@app.middleware('http')
async def security_middleware(req: Request, call_next):
    t0 = time.perf_counter()
    ip, path = client_ip(req), req.url.path
    if req.url.scheme != 'https' and path not in PLAIN_ALLOWED:
        log(30, 'http.plaintext.blocked', ip=ip, path=path)
        resp = JSONResponse({'detail': 'HTTPS required'}, status_code=403)
    elif path not in NO_RATE_LIMIT and not rl.allow_request(ip):
        log(30, 'rate.limit', ip=ip, path=path)
        resp = JSONResponse({'detail': 'Too many requests'}, status_code=429, headers={'Retry-After': '1'})
    else:
        try:
            resp = await call_next(req)
        except Exception as e:
            log(40, 'server.error', ip=ip, path=path, error=type(e).__name__)
            resp = JSONResponse({'detail': 'Internal server error'}, status_code=500)
    log(20 if resp.status_code < 400 else 30, 'request', ip=ip, method=req.method, path=path,
        scheme=req.url.scheme, status=resp.status_code, user=getattr(req.state, 'user', None),
        ms=round((time.perf_counter() - t0) * 1000, 2))
    return resp


# ----- Публічні ендпоінти -----

@app.get('/health')
def health():
    return {'ok': True, 'ts': int(time.time())}


@app.post('/echo-http')
def echo_http(e: EchoIn):
    return {'echo': e.msg}


# ----- Автентифікація -----

@app.post('/auth/login', response_model=TokenOut)
def login(req: Request, data: LoginIn):
    ip, user = client_ip(req), data.username
    wait = rl.login_blocked(ip, user)
    if wait:
        log(30, 'auth.blocked', ip=ip, user=user, retry_after=wait)
        raise HTTPException(429, 'Too many failed attempts, try later', headers={'Retry-After': str(wait)})
    account = sec.check_credentials(user, data.password)
    if account is None:
        locked = rl.login_failed(ip, user)
        log(30, 'auth.fail', ip=ip, user=user, reason='bad_credentials')
        if locked:
            log(30, 'auth.lockout', ip=ip, user=user)
        raise HTTPException(401, 'Invalid credentials')
    if sec.mfa_enabled(user):
        if not data.otp:
            log(20, 'auth.otp.required', ip=ip, user=user)
            raise HTTPException(401, 'OTP required')
        if not sec.verify_otp(user, data.otp):
            locked = rl.login_failed(ip, user)
            log(30, 'auth.fail', ip=ip, user=user, reason='bad_otp')
            if locked:
                log(30, 'auth.lockout', ip=ip, user=user)
            raise HTTPException(401, 'Invalid or reused OTP')
    rl.login_ok(ip, user)
    req.state.user = user
    log(20, 'auth.ok', ip=ip, user=user, role=account['role'], mfa=sec.mfa_enabled(user))
    return TokenOut(access_token=sec.create_token(user, account['role']), expires_in=sec.JWT_TTL)


def require_token(req: Request) -> dict:
    auth = req.headers.get('Authorization', '')
    ip = client_ip(req)
    if not auth.startswith('Bearer '):
        log(30, 'auth.token.missing', ip=ip, path=req.url.path)
        raise HTTPException(401, 'Missing token', headers={'WWW-Authenticate': 'Bearer'})
    try:
        payload = sec.decode_token(auth.split(' ', 1)[1])
    except jwt.ExpiredSignatureError:
        log(30, 'auth.token.expired', ip=ip, path=req.url.path)
        raise HTTPException(401, 'Token expired', headers={'WWW-Authenticate': 'Bearer'})
    except jwt.InvalidTokenError as e:
        log(30, 'auth.token.invalid', ip=ip, path=req.url.path, reason=str(e))
        raise HTTPException(401, 'Invalid token', headers={'WWW-Authenticate': 'Bearer'})
    req.state.user = payload['sub']
    return payload


def require_admin(req: Request, payload: dict = Depends(require_token)) -> dict:
    if payload['role'] != 'admin':
        log(30, 'access.denied', ip=client_ip(req), user=payload['sub'], role=payload['role'], path=req.url.path)
        raise HTTPException(403, 'Admin role required')
    return payload


@app.post('/auth/refresh', response_model=TokenOut)
def refresh(req: Request, payload: dict = Depends(require_token)):
    sec.revoke(payload)                          # старий токен більше не діє
    log(20, 'auth.refresh', ip=client_ip(req), user=payload['sub'])
    return TokenOut(access_token=sec.create_token(payload['sub'], payload['role']), expires_in=sec.JWT_TTL)


@app.post('/auth/logout')
def logout(req: Request, payload: dict = Depends(require_token)):
    sec.revoke(payload)
    log(20, 'auth.logout', ip=client_ip(req), user=payload['sub'])
    return {'detail': 'Logged out'}


# ----- MFA -----

@app.post('/auth/mfa/setup')
def mfa_setup(req: Request, payload: dict = Depends(require_token)):
    user = payload['sub']
    try:
        secret = sec.mfa_setup(user)
    except ValueError:
        raise HTTPException(409, 'MFA already enabled')
    uri = pyotp.TOTP(secret).provisioning_uri(name=user, issuer_name='SecureNetApp')
    log(20, 'mfa.setup', ip=client_ip(req), user=user)
    return {'secret': secret, 'otpauth_uri': uri}


@app.post('/auth/mfa/confirm')
def mfa_confirm(req: Request, data: OtpIn, payload: dict = Depends(require_token)):
    user = payload['sub']
    if not sec.mfa_confirm(user, data.otp):
        log(30, 'mfa.confirm.fail', ip=client_ip(req), user=user)
        raise HTTPException(400, 'Invalid OTP or MFA setup not started')
    log(20, 'mfa.enabled', ip=client_ip(req), user=user)
    return {'detail': 'MFA enabled'}


# ----- Захищені ендпоінти -----

@app.post('/echo-https')
def echo_https(e: EchoIn, payload: dict = Depends(require_token)):
    return {'user': payload['sub'], 'echo': e.msg}


@app.get('/whoami')
def whoami(payload: dict = Depends(require_token)):
    return {'sub': payload['sub'], 'role': payload['role'], 'exp': payload['exp'],
            'mfa': sec.mfa_enabled(payload['sub'])}


@app.get('/admin/users')
def admin_users(payload: dict = Depends(require_admin)):
    return {u: {'role': v['role'], 'mfa': sec.mfa_enabled(u)} for u, v in sec.USERS.items()}
