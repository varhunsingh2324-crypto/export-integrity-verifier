-- New app release between v1 and v2: :rows low-entropy rows, sorted by time, remarks NULL.

SET search_path = :"schema";

CREATE FUNCTION pg_temp.pick(arr text[]) RETURNS text LANGUAGE sql VOLATILE AS $$
    SELECT arr[1 + floor(random() * cardinality(arr))::int]
$$;

SELECT setseed(:seed);

INSERT INTO transactions
SELECT base.max_id + g,
       1 + floor(random() * :accounts)::int,
       date_trunc('second', :'ts_start'::timestamptz
           + (:'ts_end'::timestamptz - :'ts_start'::timestamptz) * (g::float8 / :rows)),
       pg_temp.pick(:'amounts'::text[])::numeric(12,2),
       pg_temp.pick(:'currencies'::text[]),
       pg_temp.pick(:'statuses'::text[]),
       pg_temp.pick(:'channels'::text[]),
       'M' || lpad(floor(random() * :merchants)::int::text, 6, '0'),
       NULL,
       :'meta'::jsonb
FROM (SELECT coalesce(max(id), 0) AS max_id FROM transactions) AS base,
     generate_series(1, :rows) AS g;
