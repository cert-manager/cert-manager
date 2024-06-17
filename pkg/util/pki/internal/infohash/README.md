# infohash

Am extendable hash &amp; comparator that tells you why the hash did not match.

For example if you edit the Name field in a struct, this library will tell
you that the hash did not match because the Name field was changed.

The hash is extendable, so you can add fields to the struct without breaking
the hash.

## Space Complexity

Per struct, we store a "global" hash and a "local" hash for each field.
The global hash is 64 bits long, and the local hashes are 32 bits long.
We use hamming codes to detect which "local" hash has changed. This requires
us to store log2(nr_fields+1) 32 bit parity hashes instead of nr_fields 32 bit
hashes. To store the number of fields, we use 16 bits. The total space complexity
is therefore:

```
(16 + 64 + log2(nr_fields+1) * 32) bits
= (10 + log2(nr_fields+1) * 4) bytes
= (20 + log2(nr_fields+1) * 8) hex characters
```

As a rule of thumb, this library is only useful if you have at least +-7 fields,
otherwise you can just store the hashes of each field individually.

## Safety

This library will detect any changes to the struct (with collision chance of 1/2^32, accounting for birthday attack).
However, accurately detecting which field changed is only possible if only one field changed.
If multiple fields changed, we can only detect that at least one field changed, but not which one.
This is because we use hamming codes to detect which field changed, and hamming codes can only detect
single field errors.
