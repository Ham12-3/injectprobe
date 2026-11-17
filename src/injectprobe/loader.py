"""Load attack YAML files, filter them, and render them into concrete probes."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import ValidationError

from .canary import CanaryToken
from .carriers import CARRIERS
from .models import Attack, CATEGORIES, ContextItem, Delivery, Severity
from .mutators import MUTATORS, apply_mutators


class AttackLoadError(Exception):
    pass


QUICK_TAG = "quick"


def builtin_attack_dir() -> Path:
    return Path(str(resources.files("injectprobe") / "attacks"))


def load_attack_file(path: Path) -> list[Attack]:
    """Load one YAML file.

    Format::

        category: instruction_override   # default for every attack in the file
        attacks:
          - id: io-001
            severity: high
            ...
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise AttackLoadError(f"cannot read attack file {path}: {e}") from e
    if data is None:
        return []
    if isinstance(data, list):
        data = {"attacks": data}
    if not isinstance(data, dict) or not isinstance(data.get("attacks"), list):
        raise AttackLoadError(f"{path}: expected a mapping with an 'attacks' list")
    default_category = data.get("category")
    default_tags = data.get("tags", [])
    out: list[Attack] = []
    for i, raw in enumerate(data["attacks"]):
        if not isinstance(raw, dict):
            raise AttackLoadError(f"{path}: attack #{i + 1} is not a mapping")
        raw = dict(raw)
        if default_category and "category" not in raw:
            raw["category"] = default_category
        if default_tags:
            raw["tags"] = list(dict.fromkeys([*default_tags, *raw.get("tags", [])]))
        try:
            attack = Attack.model_validate(raw)
        except ValidationError as e:
            msgs = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
            raise AttackLoadError(f"{path}: attack {raw.get('id', f'#{i + 1}')}: {msgs}") from e
        unknown = [m for m in attack.mutators if m not in MUTATORS]
        if unknown:
            raise AttackLoadError(f"{path}: attack {attack.id}: unknown mutator(s) {unknown}")
        attack.source = str(path)
        out.append(attack)
    return out


def _yaml_files(p: Path) -> list[Path]:
    if p.is_dir():
        return sorted([*p.glob("*.yaml"), *p.glob("*.yml")])
    if p.is_file():
        return [p]
    raise AttackLoadError(f"attack path not found: {p}")


def load_attacks(paths: Iterable[str | Path] = (), include_builtin: bool = True) -> list[Attack]:
    files: list[Path] = []
    if include_builtin:
        files.extend(_yaml_files(builtin_attack_dir()))
    for p in paths:
        files.extend(_yaml_files(Path(p)))
    attacks: list[Attack] = []
    seen: dict[str, str] = {}
    for f in files:
        for a in load_attack_file(f):
            if a.id in seen:
                raise AttackLoadError(f"duplicate attack id {a.id!r} in {f} and {seen[a.id]}")
            seen[a.id] = str(f)
            attacks.append(a)
    return attacks


def filter_attacks(
    attacks: list[Attack],
    *,
    categories: Iterable[str] = (),
    severities: Iterable[str] = (),
    ids: Iterable[str] = (),
    tags: Iterable[str] = (),
    exclude_ids: Iterable[str] = (),
    exclude_tags: Iterable[str] = (),
    quick: bool = False,
) -> list[Attack]:
    categories, severities, ids = set(categories), set(severities), list(ids)
    tags, exclude_ids, exclude_tags = set(tags), list(exclude_ids), set(exclude_tags)
    for s in severities:
        if s not in Severity.__members__:
            raise AttackLoadError(f"unknown severity {s!r}; use one of {', '.join(Severity.__members__)}")
    out = []
    for a in attacks:
        if categories and a.category not in categories:
            continue
        if severities and a.severity.value not in severities:
            continue
        if ids and not any(fnmatch.fnmatch(a.id, pat) for pat in ids):
            continue
        if tags and not tags.intersection(a.tags):
            continue
        if any(fnmatch.fnmatch(a.id, pat) for pat in exclude_ids):
            continue
        if exclude_tags.intersection(a.tags):
            continue
        if quick and QUICK_TAG not in a.tags:
            continue
        out.append(a)
    return out


def known_categories(attacks: Iterable[Attack]) -> list[str]:
    return sorted({*CATEGORIES, *(a.category for a in attacks)})


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TestCase:
    """An attack plus any extra run-level mutator."""

    attack: Attack
    extra_mutators: tuple[str, ...] = ()

    __test__ = False  # not a pytest class

    @property
    def id(self) -> str:
        return self.attack.id + "".join(f"~{m}" for m in self.extra_mutators)

    @property
    def mutators(self) -> list[str]:
        return [*self.attack.mutators, *self.extra_mutators]


@dataclass
class RenderedProbe:
    turns: list[str]
    context: list[ContextItem] = field(default_factory=list)

    def sent_text(self) -> str:
        return "\n".join([*self.turns, *(c.content for c in self.context)])


def expand_cases(attacks: list[Attack], run_mutators: Iterable[str] = ()) -> list[TestCase]:
    run_mutators = list(run_mutators)
    for m in run_mutators:
        if m not in MUTATORS:
            raise AttackLoadError(f"unknown mutator {m!r}; available: {', '.join(sorted(MUTATORS))}")
    cases = [TestCase(a) for a in attacks]
    for m in run_mutators:
        cases.extend(TestCase(a, (m,)) for a in attacks if m not in a.mutators)
    return cases


def fill(template: str, variables: dict[str, str]) -> str:
    """Replace ``{name}`` for known names only, leaving other braces untouched."""
    for k, v in variables.items():
        template = template.replace("{" + k + "}", v)
    return template


def render_case(case: TestCase, canary: CanaryToken) -> RenderedProbe:
    attack = case.attack
    variables = canary.variables()
    protected = canary.protected()
    texts = [apply_mutators(fill(t, variables), case.mutators, protected) for t in attack.templates]

    if attack.delivery == Delivery.direct:
        return RenderedProbe(turns=texts)

    assert attack.carrier is not None
    defaults = CARRIERS[attack.carrier]
    template = attack.carrier_template or defaults.template
    payload = texts[0]
    if template.lstrip().startswith(("{", "[")):
        payload = json.dumps(payload)[1:-1]  # keep JSON carriers valid
    content = fill(template.replace("{payload}", payload), variables)
    item = ContextItem(kind=attack.carrier, title=attack.carrier_title or defaults.title, content=content)
    question = fill(attack.user_question or defaults.question, variables)
    return RenderedProbe(turns=[question], context=[item])
