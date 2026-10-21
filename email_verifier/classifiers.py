from __future__ import annotations

import os
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
    def load(
        cls, path: str | Path | None = None, *, max_bytes: int = 5 * 1024 * 1024
    ) -> "ClassifierData":
        if path is None:
            resource = files("email_verifier").joinpath("data/disposable_domains.txt")
            lines = resource.read_text(encoding="utf-8").splitlines()
        else:
            source = Path(path)
            with source.open("r", encoding="utf-8") as handle:
                if os.fstat(handle.fileno()).st_size > max_bytes:
                    raise ValueError(f"classifier file exceeds the {max_bytes} byte limit")
                lines = handle.read().splitlines()
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
