from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

DEFAULT_ROLE_PREFIXES = frozenset(
    {
        "admin",
        "billing",
        "contact",
        "info",
        "hello",
        "help",
        "office",
        "sales",
        "support",
        "webmaster",
    }
)


@dataclass(frozen=True, slots=True)
class ClassifierData:
    disposable_domains: frozenset[str]
    role_prefixes: frozenset[str] = DEFAULT_ROLE_PREFIXES

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ClassifierData":
        if path is None:
            resource = files("email_verifier").joinpath("data/disposable_domains.txt")
            lines = resource.read_text(encoding="utf-8").splitlines()
        else:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        domains = frozenset(
            line.strip().lower().lstrip(".")
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
        return cls(disposable_domains=domains)

    def is_disposable(self, domain: str) -> bool:
        domain = domain.lower()
        return any(
            domain == item or domain.endswith("." + item) for item in self.disposable_domains
        )

    def is_role_based(self, local_part: str) -> bool:
        return local_part.strip('"').split("+", 1)[0].lower() in self.role_prefixes
