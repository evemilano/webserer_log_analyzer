"""Classificazione degli user agent secondo `config/bots.yaml`.

Le regole sono dati, non codice: aggiungere un bot significa aggiungere sei
righe di YAML. L'ordine del file è l'ordine di valutazione e il primo match
vince, il che rende la classificazione prevedibile e discutibile guardando
solo il file di configurazione.

La classificazione si applica agli **user agent distinti**, non alle righe:
sui 13 mesi di evemilano.com sono 529.968 stringhe distinte contro 7,45
milioni di righe. Il risultato torna sulle righe con una join.

La v1 di questo applicativo teneva le stesse regole in un CSV e ci aveva
accumulato tre problemi che qui non si ripetono: `meta-externalagent` era
presente due volte con due strategie di verifica diverse e vinceva l'ultima
letta, per cui la verifica Facebook spariva senza dire niente; tre coppie di
bot condividevano il `bot_name` e collidevano nel dizionario; e i pattern con
metacaratteri (`omgili|omgilibot`) o con spazi (`screaming frog`) finivano in
un mega-regex concatenato dove il lookup inverso del nome non funzionava più.
Qui ogni regola ha un `id` univoco, verificato al caricamento.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import polars as pl
import yaml

from .config import CONFIG_DIR

log = logging.getLogger(__name__)

BOTS_FILE = CONFIG_DIR / "bots.yaml"

CATEGORIES = {
    "Browser",
    "Search engine bot",
    "AI bot",
    "AI Agents bot",
    "Python bot",
    "General bot",
}


class ClassifyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    ua_regex: str | None = None
    subcategory: str | None = None
    ip_sources: tuple[str, ...] = ()
    rdns_suffixes: tuple[str, ...] = ()

    @property
    def verifiable(self) -> bool:
        return bool(self.ip_sources or self.rdns_suffixes)


@dataclass
class Ruleset:
    rules: list[Rule]
    fallback_bot: Rule
    fallback_browser: Rule
    no_user_agent: Rule
    fallback_bot_hint: str
    case_insensitive: bool = True
    _by_id: dict[str, Rule] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_id = {r.id: r for r in self.all_rules}

    @property
    def all_rules(self) -> list[Rule]:
        return [*self.rules, self.fallback_bot, self.fallback_browser, self.no_user_agent]

    def by_id(self, rule_id: str) -> Rule:
        return self._by_id[rule_id]

    def verifiable_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.verifiable]


def _flags(pattern: str, case_insensitive: bool) -> str:
    return f"(?i){pattern}" if case_insensitive else pattern


def load_rules(path: Path | None = None) -> Ruleset:
    path = path or BOTS_FILE
    if not path.exists():
        raise FileNotFoundError(f"Manca {path}")
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ClassifyError(f"{path}: la chiave `rules` deve essere una lista non vuota")

    case_insensitive = bool(data.get("case_insensitive", True))
    rules: list[Rule] = []
    seen: set[str] = set()

    for position, item in enumerate(raw_rules):
        for required in ("id", "ua_regex", "name", "category"):
            if required not in item:
                raise ClassifyError(f"{path}: regola in posizione {position} senza `{required}`")
        rule_id = item["id"]
        if rule_id in seen:
            raise ClassifyError(f"{path}: id di regola duplicato: {rule_id!r}")
        seen.add(rule_id)

        if item["category"] not in CATEGORIES:
            raise ClassifyError(
                f"{path}: regola {rule_id!r} ha categoria {item['category']!r}; "
                f"le categorie previste sono {sorted(CATEGORIES)}"
            )

        pattern = _flags(item["ua_regex"], case_insensitive)
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ClassifyError(f"{path}: regola {rule_id!r} ha una regex non valida: {exc}") from exc

        verify = item.get("verify") or {}
        rules.append(
            Rule(
                id=rule_id,
                name=item["name"],
                category=item["category"],
                ua_regex=pattern,
                subcategory=item.get("subcategory"),
                ip_sources=tuple(verify.get("ip_sources") or ()),
                rdns_suffixes=tuple(verify.get("rdns_suffixes") or ()),
            )
        )

    def _special(key: str, default_category: str) -> Rule:
        node = data.get(key) or {}
        return Rule(
            id=f"__{key}__",
            name=node.get("name", key),
            category=node.get("category", default_category),
        )

    ruleset = Ruleset(
        rules=rules,
        fallback_bot=_special("fallback_bot", "General bot"),
        fallback_browser=_special("fallback_browser", "Browser"),
        no_user_agent=_special("no_user_agent", "General bot"),
        fallback_bot_hint=_flags(
            data.get("fallback_bot_hint", "bot|crawl|spider"), case_insensitive
        ),
        case_insensitive=case_insensitive,
    )

    # Un `ip_sources` che punta a una fonte inesistente farebbe fallire ogni
    # verifica in silenzio: meglio accorgersene qui.
    try:
        from .ipranges import load_sources

        known = {s.id for s in load_sources()}
        for rule in rules:
            unknown = set(rule.ip_sources) - known
            if unknown:
                log.warning(
                    "bots.yaml: la regola %r cita fonti IP inesistenti in bot_sources.yaml: %s",
                    rule.id, ", ".join(sorted(unknown)),
                )
    except Exception as exc:  # la validazione incrociata non deve bloccare
        log.debug("Validazione incrociata con bot_sources.yaml saltata: %s", exc)

    log.info(
        "bots.yaml: %d regole (%d verificabili), %d categorie usate",
        len(rules),
        len(ruleset.verifiable_rules()),
        len({r.category for r in rules}),
    )
    return ruleset


# --------------------------------------------------------------------------
# applicazione
# --------------------------------------------------------------------------


def classify_user_agents(user_agents: pl.Series, ruleset: Ruleset) -> pl.DataFrame:
    """Classifica un insieme di user agent distinti.

    Ritorna un DataFrame con `user_agent, bot_id, bot, category, subcategory`,
    pronto per una join sulle righe degli eventi.
    """
    df = pl.DataFrame({"user_agent": user_agents})

    # L'indice della prima regola che matcha. Si costruisce al contrario così
    # che le regole precedenti nel file sovrascrivano le successive: è il modo
    # più diretto di rendere "primo match vince" una singola espressione.
    index = pl.lit(None, dtype=pl.Int32)
    for position in range(len(ruleset.rules) - 1, -1, -1):
        rule = ruleset.rules[position]
        index = (
            pl.when(pl.col("user_agent").str.contains(rule.ua_regex))
            .then(pl.lit(position, dtype=pl.Int32))
            .otherwise(index)
        )

    df = df.with_columns(index.alias("_rule"))

    lookup = pl.DataFrame(
        {
            "_rule": pl.Series([i for i in range(len(ruleset.rules))], dtype=pl.Int32),
            "bot_id": [r.id for r in ruleset.rules],
            "bot": [r.name for r in ruleset.rules],
            "category": [r.category for r in ruleset.rules],
            "subcategory": [r.subcategory for r in ruleset.rules],
        }
    )
    df = df.join(lookup, on="_rule", how="left")

    # Nessuna regola ha matchato: si sceglie fra i due fallback in base a come
    # lo user agent si presenta. Lo user agent assente è un caso a sé.
    fb_bot, fb_browser, fb_none = ruleset.fallback_bot, ruleset.fallback_browser, ruleset.no_user_agent
    looks_like_bot = pl.col("user_agent").str.contains(ruleset.fallback_bot_hint)

    def _fill(column: str, attribute: str) -> pl.Expr:
        return (
            pl.when(pl.col(column).is_not_null())
            .then(pl.col(column))
            .when(pl.col("user_agent").is_null())
            .then(pl.lit(getattr(fb_none, attribute)))
            .when(looks_like_bot)
            .then(pl.lit(getattr(fb_bot, attribute)))
            .otherwise(pl.lit(getattr(fb_browser, attribute)))
            .alias(column)
        )

    df = df.with_columns(
        [
            _fill("bot_id", "id"),
            _fill("bot", "name"),
            _fill("category", "category"),
        ]
    )

    return df.select(["user_agent", "bot_id", "bot", "category", "subcategory"])
