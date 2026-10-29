-- Data-privacy job between v1 and v2: rows older than :cutoff lose remarks and some meta keys.

SET search_path = :"schema";

UPDATE transactions
SET remarks = NULL,
    meta = meta - :'meta_drop_keys'::text[]
WHERE txn_ts < :'cutoff'::timestamptz;
