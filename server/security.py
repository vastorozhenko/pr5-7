import json, os, secrets, threading, time
from typing import Optional
import bcrypt, jwt, pyotp

# ----- Налаштування -----
JWT_SECRET = os.environ.get('JWT_SECRET', '')
if len(JWT_SECRET) < 32:
    raise RuntimeError('JWT_SECRET is not set or shorter than 32 characters (see .env.example)')
JWT_ALG = 'HS256'
JWT_ISS = 'secure-net-app'
JWT_TTL = int(os.environ.get('JWT_TTL', '900'))      # 15 хв

USERS_PATH = 'server/users.json'                     # облікові записи: bcrypt-хеші і ролі
MFA_PATH = os.environ.get('MFA_PATH', 'server/data/mfa.json')   # секрети TOTP (не в git)

with open(USERS_PATH, 'r', encoding='utf-8') as f:
    USERS = json.load(f)

_lock = threading.Lock()
_DUMMY_HASH = bcrypt.hashpw(b'dummy-password', bcrypt.gensalt(12))
_revoked = {}          # jti -> exp: відкликані токени (вихід, оновлення)
_last_otp = {}         # user -> останній використаний крок TOTP (захист від повтору коду)


def _load_mfa():
    if os.path.exists(MFA_PATH):
        with open(MFA_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


MFA = _load_mfa()      # {"alice": {"secret": "...", "enabled": true}}


def _save_mfa():
    os.makedirs(os.path.dirname(MFA_PATH), exist_ok=True)
    fd = os.open(MFA_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(MFA, f, indent=2)


# ----- Паролі -----

def check_credentials(username: str, password: str) -> Optional[dict]:
    """Повертає користувача або None. Для неіснуючого користувача теж виконується bcrypt,
    щоб за часом відповіді не можна було визначити, чи існує логін."""
    user = USERS.get(username)
    hashed = user['pwd'].encode() if user else _DUMMY_HASH
    ok = bcrypt.checkpw(password.encode(), hashed)
    return user if (user and ok) else None


# ----- JWT -----

def create_token(sub: str, role: str, ttl: int = None) -> str:
    now = int(time.time())
    payload = {'sub': sub, 'role': role, 'iss': JWT_ISS, 'iat': now,
               'exp': now + (JWT_TTL if ttl is None else ttl), 'jti': secrets.token_hex(8)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(tok: str) -> dict:
    """Перевіряє підпис, алгоритм, видавця, термін дії і відкликання.
    Кидає jwt.ExpiredSignatureError або jwt.InvalidTokenError."""
    payload = jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALG], issuer=JWT_ISS,
                         options={'require': ['sub', 'role', 'iat', 'exp', 'jti']})
    if payload['jti'] in _revoked:
        raise jwt.InvalidTokenError('token revoked')
    if payload['sub'] not in USERS or USERS[payload['sub']]['role'] != payload['role']:
        raise jwt.InvalidTokenError('unknown user or role')
    return payload


def revoke(payload: dict):
    now = int(time.time())
    with _lock:
        for j in [j for j, exp in _revoked.items() if exp < now]:
            del _revoked[j]                      # прострочені токени вже не потрібно пам'ятати
        _revoked[payload['jti']] = payload['exp']


# ----- MFA (TOTP) -----

def mfa_enabled(username: str) -> bool:
    return MFA.get(username, {}).get('enabled', False)


def mfa_setup(username: str) -> str:
    """Новий секрет зберігається як непідтверджений, доки користувач не введе код із застосунку."""
    if mfa_enabled(username):
        raise ValueError('MFA already enabled')
    secret = pyotp.random_base32()
    with _lock:
        MFA[username] = {'secret': secret, 'enabled': False}
        _save_mfa()
    return secret


def _check_otp(username: str, otp: Optional[str]) -> bool:
    rec = MFA.get(username)
    if not rec or not otp:
        return False
    totp = pyotp.TOTP(rec['secret'])
    now = time.time()
    for drift in (0, -1, 1):                     # допускається відхилення годинника на один крок (30 с)
        step = totp.timecode(now) + drift
        if secrets.compare_digest(totp.generate_otp(step), otp):
            if _last_otp.get(username, -1) >= step:
                return False                     # код уже використано
            _last_otp[username] = step
            return True
    return False


def mfa_confirm(username: str, otp: str) -> bool:
    if username not in MFA or mfa_enabled(username) or not _check_otp(username, otp):
        return False
    with _lock:
        MFA[username]['enabled'] = True
        _save_mfa()
    return True


def verify_otp(username: str, otp: Optional[str]) -> bool:
    if not mfa_enabled(username):
        return True                              # MFA не ввімкнено
    return _check_otp(username, otp)
