"""Hand-crafted pg_dump 16 plain-format dumps for tests, laid out exactly like the real one
(`zcat data/exports/v1.sql.gz`): header, `\\restrict`, SETs, CREATE TABLE, COPY, `\\.`, the
PRIMARY KEY after the data, completion marker, `\\unrestrict`."""

import random

KEY = "TestRestrictKey0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
TABLE = "public.transactions"
COLUMNS = (
    "id",
    "account_id",
    "txn_ts",
    "amount",
    "currency",
    "status",
    "channel",
    "merchant_code",
    "remarks",
    "meta",
)

PREAMBLE = f"""--
-- PostgreSQL database dump
--

\\restrict {KEY}

-- Dumped from database version 16.15 (Debian 16.15-1.pgdg13+2)
-- Dumped by pg_dump version 16.15 (Debian 16.15-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

"""

DDL = f"""--
-- Name: transactions; Type: TABLE; Schema: public; Owner: eguard
--

CREATE TABLE {TABLE} (
    id bigint NOT NULL,
    account_id integer NOT NULL,
    txn_ts timestamp with time zone NOT NULL,
    amount numeric(12,2) NOT NULL,
    currency character(3) NOT NULL,
    status text NOT NULL,
    channel text NOT NULL,
    merchant_code text NOT NULL,
    remarks text,
    meta jsonb
)
WITH (autovacuum_enabled='false');


ALTER TABLE {TABLE} OWNER TO eguard;

"""

COPY_HEADER = f"""--
-- Data for Name: transactions; Type: TABLE DATA; Schema: public; Owner: eguard
--

COPY {TABLE} ({", ".join(COLUMNS)}) FROM stdin;
"""

POST_DATA = f"""\\.


--
-- Name: transactions transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: eguard
--

ALTER TABLE ONLY {TABLE}
    ADD CONSTRAINT transactions_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\\unrestrict {KEY}

"""

# COPY-escaped free text exercising every escape pg_dump emits.
TRICKY = ["tab\\there", "line\\nbreak", "back\\\\slash", "café ☃", "cr\\rlf"]


def row(i: int, rng: random.Random) -> str:
    remarks = "\\N" if i % 7 == 0 else (TRICKY[i % len(TRICKY)] if i % 5 == 0 else f"{i:x}" * 3)
    meta = "\\N" if i % 11 == 0 else f'{{"v": 1, "risk": {i % 100}, "note": "q\\\\"x"}}'
    ts = f"2023-{1 + i % 12:02d}-{1 + i % 28:02d} {i % 24:02d}:{i % 60:02d}:{i % 60:02d}.{i:06d}"
    fields = [
        str(i),
        str(rng.randrange(1, 200_000)),
        ts[:26] + "+00",
        f"{rng.randrange(0, 500_000) / 100:.2f}",
        rng.choice(["USD", "EUR", "GBP"]),
        rng.choice(["settled", "pending"]),
        rng.choice(["web", "pos", "api"]),
        f"M{rng.randrange(50_000):06d}",
        remarks,
        meta,
    ]
    return "\t".join(fields)


def rows(n: int, seed: int = 7, start: int = 1) -> list[str]:
    rng = random.Random(seed)
    return [row(i, rng) for i in range(start, start + n)]


def dump_text(n_rows: int = 200, *, body: list[str] | None = None) -> str:
    """A complete, healthy dump; `body` replaces the generated COPY rows if given."""
    data = rows(n_rows) if body is None else body
    return PREAMBLE + DDL + COPY_HEADER + "".join(r + "\n" for r in data) + POST_DATA


def dump_bytes(n_rows: int = 200, *, body: list[str] | None = None) -> bytes:
    return dump_text(n_rows, body=body).encode()


def killed_at(n_rows: int, keep_rows: int, partial: str = "1234\t56") -> bytes:
    """What `pg_dump | gzip` leaves when pg_dump dies after `keep_rows` rows plus a partial one."""
    text = PREAMBLE + DDL + COPY_HEADER + "".join(r + "\n" for r in rows(n_rows)[:keep_rows])
    return (text + partial).encode()


def header_lines() -> int:
    """Line number of the COPY header in dump_text()."""
    return (PREAMBLE + DDL + COPY_HEADER).count("\n")
