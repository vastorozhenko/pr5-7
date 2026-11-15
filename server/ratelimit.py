import os, threading, time

# Два механізми:
# 1) захист від перебору пароля: невдалі спроби входу рахуються для пари (IP, логін) і для IP
#    у ковзному вікні; після перевищення ліміту вхід тимчасово блокується;
# 2) захист від флуду (DDoS): token bucket на IP для захищених ендпоінтів.

LOGIN_FAILS = int(os.environ.get('LOGIN_FAILS', '5'))         # невдалих спроб на (IP, логін)
IP_FAILS = int(os.environ.get('IP_FAILS', '20'))              # невдалих спроб на IP (будь-які логіни)
FAIL_WINDOW = int(os.environ.get('FAIL_WINDOW', '300'))       # вікно, с
LOCK_SECONDS = int(os.environ.get('LOCK_SECONDS', '300'))     # тривалість блокування, с
RATE_RPS = float(os.environ.get('RATE_RPS', '10'))            # запитів/с на IP
RATE_BURST = int(os.environ.get('RATE_BURST', '20'))          # допустимий сплеск


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self.fails = {}         # key -> [час невдалих спроб]
        self.locked = {}        # key -> час завершення блокування
        self.buckets = {}       # ip -> (токени, час)

    def _prune(self, key, now):
        self.fails[key] = [t for t in self.fails.get(key, []) if now - t < FAIL_WINDOW]

    def login_blocked(self, ip: str, username: str) -> int:
        """0 - вхід дозволено, інакше скільки секунд залишилось до розблокування."""
        now = time.time()
        with self._lock:
            until = max(self.locked.get(('u', ip, username), 0), self.locked.get(('ip', ip), 0))
            return int(until - now) + 1 if until > now else 0

    def login_failed(self, ip: str, username: str) -> bool:
        """Фіксує невдалу спробу; True, якщо після неї ввімкнено блокування."""
        now = time.time()
        locked = False
        with self._lock:
            for key, limit in ((('u', ip, username), LOGIN_FAILS), (('ip', ip), IP_FAILS)):
                self._prune(key, now)
                self.fails[key].append(now)
                if len(self.fails[key]) >= limit:
                    self.locked[key] = now + LOCK_SECONDS
                    self.fails[key] = []
                    locked = True
        return locked

    def login_ok(self, ip: str, username: str):
        with self._lock:
            self.fails.pop(('u', ip, username), None)

    def allow_request(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            tokens, ts = self.buckets.get(ip, (RATE_BURST, now))
            tokens = min(RATE_BURST, tokens + (now - ts) * RATE_RPS)
            if tokens < 1:
                self.buckets[ip] = (tokens, now)
                return False
            self.buckets[ip] = (tokens - 1, now)
            return True
