"""RateLimitService: límites globales, por host y por programa (token bucket).

Determinista y testeable: el reloj se inyecta, no se usa sleep. Implementa el
'Safe Scan por defecto' del spec (20 req/s global inicial, límites por host y
programa, concurrencia acotada).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


class TokenBucket:
    """Cubo de tokens clásico. try_acquire() no bloquea."""

    def __init__(self, rate: float, capacity: float, now: float = 0.0) -> None:
        if rate <= 0:
            raise ValueError("rate debe ser > 0")
        if capacity <= 0:
            raise ValueError("capacity debe ser > 0")
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last = now

    def refill(self, now: float) -> None:
        if now > self._last:
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now

    def available(self, now: float) -> float:
        self.refill(now)
        return self._tokens

    def consume(self, tokens: float = 1.0) -> None:
        self._tokens -= tokens

    def try_acquire(self, now: float, tokens: float = 1.0) -> bool:
        if self.available(now) >= tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def tokens(self) -> float:
        return self._tokens


@dataclass
class RateLimitConfig:
    """Tasas (req/s) y capacidades de ráfaga."""

    global_rps: float = 20.0
    per_program_rps: float = 10.0
    per_host_rps: float = 5.0
    burst_factor: float = 1.0


class RateLimitService:
    """Compone límites global + por programa + por host. Deny si alguno bloquea."""

    def __init__(
        self,
        config: RateLimitConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config or RateLimitConfig()
        self._clock = clock or (lambda: 0.0)
        self._global = self._bucket(self.config.global_rps)
        self._programs: dict[str, TokenBucket] = {}
        self._hosts: dict[str, TokenBucket] = {}

    def _bucket(self, rps: float) -> TokenBucket:
        now = self._clock()
        return TokenBucket(rate=rps, capacity=max(1.0, rps * self.config.burst_factor), now=now)

    def allow(self, program: str, host: str) -> tuple[bool, str]:
        """¿Se permite una petición ahora? Consume de los tres cubos (todo-o-nada)."""
        now = self._clock()
        prog = self._programs.setdefault(program, self._bucket(self.config.per_program_rps))
        host_bucket = self._hosts.setdefault(host, self._bucket(self.config.per_host_rps))

        # Rellenar y comprobar crédito en los tres sin consumir todavía.
        if self._global.available(now) < 1.0:
            return (False, "denegado: límite global agotado")
        if prog.available(now) < 1.0:
            return (False, f"denegado: límite de programa agotado ({program})")
        if host_bucket.available(now) < 1.0:
            return (False, f"denegado: límite de host agotado ({host})")

        # Todos tienen crédito: consumir atómicamente.
        self._global.consume()
        prog.consume()
        host_bucket.consume()
        return (True, "permitido")


@dataclass
class Budget:
    """Presupuesto de peticiones (por tarea o por campaña)."""

    limit: int
    spent: int = 0

    def try_spend(self, n: int = 1) -> bool:
        if n <= 0:
            raise ValueError("n debe ser > 0")
        if self.spent + n > self.limit:
            return False
        self.spent += n
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.limit


@dataclass
class BudgetTracker:
    """Presupuesto por tarea y por campaña; ambos deben tener crédito."""

    task_limit: int
    campaign_limit: int
    _tasks: dict[str, Budget] = field(default_factory=dict)
    _campaign: Budget | None = None

    def _campaign_budget(self) -> Budget:
        if self._campaign is None:
            self._campaign = Budget(self.campaign_limit)
        return self._campaign

    def try_spend(self, task_id: str, n: int = 1) -> tuple[bool, str]:
        task = self._tasks.setdefault(task_id, Budget(self.task_limit))
        campaign = self._campaign_budget()
        if task.remaining < n:
            return (False, f"denegado: presupuesto de tarea agotado ({task_id})")
        if campaign.remaining < n:
            return (False, "denegado: presupuesto de campaña agotado")
        task.try_spend(n)
        campaign.try_spend(n)
        return (True, "permitido")

    def task_remaining(self, task_id: str) -> int:
        return self._tasks.get(task_id, Budget(self.task_limit)).remaining

    @property
    def campaign_remaining(self) -> int:
        return self._campaign_budget().remaining
