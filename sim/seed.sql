-- Create and load :schema.transactions (IMPLEMENTATION_PLAN.md §6).
-- Run by sim/incident.py via `psql -v ...`; every knob comes from config/sim.yaml.
-- Rows are generated server-side with generate_series; setseed() makes random() reproducible.

CREATE SCHEMA IF NOT EXISTS :"schema";
SET search_path = :"schema";
DROP TABLE IF EXISTS transactions;

-- autovacuum off: heap order (and so pg_dump's byte stream) must depend only on our statements.
CREATE TABLE transactions (
    id            bigint PRIMARY KEY,
    account_id    int NOT NULL,
    txn_ts        timestamptz NOT NULL,
    amount        numeric(12,2) NOT NULL,
    currency      char(3) NOT NULL,
    status        text NOT NULL,
    channel       text NOT NULL,
    merchant_code text NOT NULL,
    remarks       text,
    meta          jsonb
) WITH (autovacuum_enabled = false);

-- n random hex characters; VOLATILE so it is evaluated per row.
CREATE FUNCTION pg_temp.hex(n int) RETURNS text LANGUAGE sql VOLATILE AS $$
    SELECT left(string_agg(md5(random()::text), ''), n)
    FROM generate_series(1, (n + 31) / 32)
$$;

CREATE FUNCTION pg_temp.pick(arr text[]) RETURNS text LANGUAGE sql VOLATILE AS $$
    SELECT arr[1 + floor(random() * cardinality(arr))::int]
$$;

SELECT setseed(:seed);

INSERT INTO transactions
SELECT g,
       1 + floor(random() * :accounts)::int,
       :'ts_start'::timestamptz + random() * (:'ts_end'::timestamptz - :'ts_start'::timestamptz),
       round((random() * 5000)::numeric, 2),
       pg_temp.pick(:'currencies'::text[]),
       pg_temp.pick(:'statuses'::text[]),
       pg_temp.pick(:'channels'::text[]),
       'M' || lpad(floor(random() * :merchants)::int::text, 6, '0'),
       pg_temp.hex(:remarks_chars),
       jsonb_build_object('risk', floor(random() * 100)::int, 'v', 1,
                          'trace', pg_temp.hex(:meta_trace_chars))
FROM generate_series(1, :rows) AS g;
