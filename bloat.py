"""
A minimalistic key stretching algorithm that requires large amounts of cpu-time
and memory.

The algorithm in pseudo-code:

initialize hasher with the key to be stretched
for each iteration:
  append the digest of hasher to end of a list
  calculate a random position within the list based on the last digest
  update the hasher with data from this random position

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
"""

from struct import unpack
from multiprocessing import Pool

def bloat(key, iterations, hashfunc):
  """The 'bloat' algorithm takes a key to be stretched, a number of iterations
  and a hashing function. Each iteration adds a memory requirement equal to the
  digest size of the hashing function, and the CPU-time required to update the
  hashing function with data of the same size. 
  
  It returns a digest size hash as the stretched key.
  """
  a = []
  h = hashfunc(key)
  for c in xrange(iterations):
    # Append the current digest to the end of the array.
    a.append(h.digest())
    # Calculate a random position from the last 8 bytes of the added item.
    random_pos = unpack("!Q", a[-1][:8])[0] % (c+1)
    # Feed the value found at the random position 
    h.update(a[random_pos])
  # The last digest is our stretched key.
  return h.digest()

def _b(args):
  """Needed to unpack the single argument style used by Pool.imap.
  """
  return bloat(*args)

def multibloat(key, iterations, hashfunc, processes):
  """The 'multibloat' algorithm expands upon 'bloat' with an additional
  argument specifying a number of processes. It then creates one key for each
  process by appending the process number to the original key, runs 'bloat' for
  each process with the derived key, and hashes the combined output as the
  stretched key.

  The most efficient configuration for any given machine is to have processes
  be equal to the number of CPU cores. This is not a requirement, and any
  number of is valid regardless of the actual CPU cores available.

  The memory requirement is iterations * processes * digest size, in addition
  to overhead.
  """
  pool = Pool(processes = processes)
  # Create unique keys by appending each process number to the initial key.
  keys = (hashfunc(key + str(x)).digest() for x in xrange(processes))
  # Run one 'bloat' process with each key.
  digests = tuple(pool.imap(_b, ((k, iterations, hashfunc) for k in keys)))
  pool.close(); pool.join()
  # Concatenate the resulting digests and hash it to make our stretched key.
  return hashfunc("".join(digests)).digest()

def iterations_to_memory(iterations, hashfunc):
  """Calculate the amount of memory required for the given number of iterations
  and the given hashfunc.
  """
  return hashfunc().digest_size * iterations

def memory_to_iterations(memory, hashfunc):
  """Calculate the number of iterations needed to consume the given amount of
  memory with the given hashfunc.
  """
  return memory / hashfunc().digest_size

def crazybloat(key, iterations, hashfunc):
  """Implements 'bloat' without storing any data already calculated. Extremely
  inefficient.
  """
  hasher = hashfunc(key)
  for c in xrange(iterations):
    random_pos = unpack("!Q", hasher.digest()[:8])[0] % (c+1)
    hasher.update(crazybloat(key, random_pos, hashfunc))
  return hasher.digest()

def integrity_test():
  from hashlib import sha512
  bloat_expect = (
      "12054e5c7c35696b662caf49edace500367c7b5971486ba4cabe25c3e7a070f1"
      "2eb4b7772c8e3f29dd8939a23ea3be36c011751d8334293798654296757c5263")
  assert bloat("test", 1024, sha512).encode('hex') == bloat_expect
  multibloat_expect = (
      "c2335a69537f9cd2adcf7d9846a3adf4ffcb22261f958e9de8ba1b82217d3591"
      "8dd35fd19cf0c3eee1a2d12eaedc230acd1f01b83cf70aed2242c8d6ec4c23da")
  assert multibloat("test", 1024, sha512, 4).encode('hex') == multibloat_expect

if __name__ == "__main__":
  integrity_test()
