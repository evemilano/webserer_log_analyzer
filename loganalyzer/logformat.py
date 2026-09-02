"""Costruzione del parser a partire dalla direttiva `log_format` di nginx.

Il parser non è scritto a mano per il formato `combined`: si genera dalla
stringa di formato dichiarata nella configurazione del sito, così lo stesso
codice serve siti con `log_format` diversi senza toccare Python.

Note sull'escaping, che è il punto dove i parser ingenui sbagliano:

nginx, nei campi fra virgolette, sostituisce `"` con `\\x22` e `\\` con
`\\x5C`, e ogni byte non stampabile con la sua forma `\\xNN`. Quindi dentro
un campo quotato non compare mai una virgoletta vera, e la regex non ha
ambiguità da risolvere. Uno spazio invece resta uno spazio: `$request` può
contenerne più di due (`"GET /a b c HTTP/1.1"`), ed è il motivo per cui
spezzare la riga sugli spazi — con `awk` o con `split()` — disallinea i
campi su una parte del traffico.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Formati con un nome riservato in nginx: se la config dichiara solo il nome,
# lo si espande nella stringa corrispondente.
NAMED_FORMATS = {
    "combined": (
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent"'
    ),
    "common": (
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent'
    ),
}

TIME_LOCAL_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

_VAR_RE = re.compile(r"\$([A-Za-z0-9_]+)")

# Campo fra virgolette: nessuna virgoletta vera può comparire all'interno,
# ma si tollera comunque una sequenza di escape per non essere fragili.
_QUOTED = r'((?:[^"\\]|\\.)*)'
_BRACKETED = r"([^\]]*)"
_BARE = r"(\S*)"


class LogFormatError(ValueError):
    pass


@dataclass(frozen=True)
class LogFormat:
    """Formato di log compilato in una regex con gruppi nominati."""

    source: str
    pattern: str
    fields: tuple[str, ...]

    @property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern)

    def __contains__(self, field: str) -> bool:
        return field in self.fields


def build(fmt: str) -> LogFormat:
    """Compila una stringa `log_format` in una regex con gruppi nominati."""
    source = fmt.strip()
    expanded = NAMED_FORMATS.get(source, source)

    if "$" not in expanded:
        raise LogFormatError(
            f"Il log_format {source!r} non contiene variabili. "
            f"Usa uno dei nomi noti ({', '.join(NAMED_FORMATS)}) o la stringa completa."
        )

    parts: list[str] = ["^"]
    fields: list[str] = []
    cursor = 0

    for match in _VAR_RE.finditer(expanded):
        literal = expanded[cursor : match.start()]
        name = match.group(1)
        following = expanded[match.end() : match.end() + 1]

        if name in fields:
            raise LogFormatError(f"Variabile ${name} ripetuta nel log_format: {source!r}")

        if literal.endswith('"') and following == '"':
            body = _QUOTED
        elif literal.endswith("[") and following == "]":
            body = _BRACKETED
        else:
            body = _BARE

        parts.append(re.escape(literal))
        # `(?P<name>...)` invece di `(?<name>...)`: è l'unica sintassi di gruppo
        # nominato che accettano sia il modulo `re` di Python sia il motore
        # regex di Rust usato da Polars, e la stessa stringa serve entrambi.
        parts.append(f"(?P<{name}>{body[1:-1]})")
        fields.append(name)
        cursor = match.end()

    parts.append(re.escape(expanded[cursor:]))
    parts.append("$")

    pattern = "".join(parts)
    try:
        re.compile(pattern)
    except re.error as exc:  # pragma: no cover - difeso da _VAR_RE
        raise LogFormatError(f"Regex non valida generata da {source!r}: {exc}") from exc

    return LogFormat(source=source, pattern=pattern, fields=tuple(fields))


def unescape(value: str) -> str:
    """Riporta le sequenze `\\xNN` di nginx ai byte originali.

    Usata solo dove il valore leggibile conta davvero (report, file degli
    errori). Nei Parquet i campi restano come li ha scritti nginx: per le
    richieste malformate — handshake TLS arrivati sulla porta 80 — la forma
    `\\x16\\x03\\x01` dice più del byte grezzo corrispondente.
    """

    def _replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    return re.sub(r"\\x([0-9A-Fa-f]{2})", _replace, value)
