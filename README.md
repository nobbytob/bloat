bloat
=====

A minimalistic key stretching algorithm with high cpu-time and memory requirements

The algorithm in pseudo-code
----------------------------

```
initialize hasher with the key to be stretched
for each iteration:
  append the digest of hasher to end of a list
  calculate a random position within the list based on the last digest
  update the hasher with data from this random position
```

Comments
--------

The cpu-time requirements of this algorithm assumed to be at least as strong as
hashing N digest size items of data.

The memory requirements is N * digest size for maximum efficiency. A scheme
that wishes to use less memory will have to do a certain amount of
recalculations. On one extreme, using the minimum amount of data and
recalculating everything all the time quickly becomes unfeasible. On the other
hand, storing checkpoints of the hash state for every 2nd iteration will only
require a modest amount of recalculations, but saves only 50% of the memory.
Thus an arbitrary amount of memory can be saved, which must be directly
compensated for by doing more CPU work. Since the number of recalculations
required grows exponentially, there will be limits as to how much memory can be
reasonably saved.

Using a hashing function as source of random data is unproven. This should not
pose a problem to this algorithm. Even if it does turn out that creating
entropy by hashing is not strictly speaking a cryptographically secure PRNG, it
is assumed that any discernible predictability will be of very limited use in
reducing the memory requirement of the algorithm.
