# MEM-01 source lifecycle review

The bounded source investigator (/root/memory_source_audit, GPT-6 Luna xhigh)
reviewed selected NNpsk0/XX, X25519, ChaChaPoly and SHA256 lifecycle code without
edits or runtime tests. The coordinator checked its claims against the source.

## Confirmed defect and repair

In Noise fork cfb45b9, handshakestate.c's internal constructor stores its new
object in the caller's output, then creates the DH children. On a child creation
error it destroys that object but leaves the output pointer dangling. Both
public constructors start by setting the output to NULL. Although their prose
does not explicitly promise NULL on every failure, returning freed storage is
an ownership hazard: ordinary conditional cleanup can free the same object twice.
The experiment reproduced this at NNpsk0 allocation ordinal 5 without
dereferencing/freeing the dangling value. The coordinator clears the output
after destruction; all 36 allocation ordinals across the two modes subsequently
pass in normal and Release builds.

## Rejected claim

The investigator initially also claimed that a failed size-changing prologue
replacement leaves the freed old pointer dangling. The coordinator rejected
this: state->prologue = malloc(prologue_len) assigns NULL on failure before the
error branch. The investigator rechecked and retracted the claim. The old
configuration is lost, but destruction does not double-free that buffer. No
prologue repair is warranted by this claim.

## Ownership and limits

- The handshake owns symmetric state, DH objects, inline PSK and prologue.
  Partial destruction recursively frees existing children; noise_free clears
  the complete requested block using noise_clean's volatile byte writes.
- Start mixes inputs without a heap request. Read/write error marks FAILED;
  the application remains responsible for destroying the owner. Read wipes
  its mutable message input. Output validity must follow the returned status.
- Split transfers the existing cipher and creates a second cipher. On allocation
  failure its outputs are NULL, temporary derived keys are cleared and the
  original cipher remains owned by the handshake. No automatic abort/retry.
- After successful Split the application owns both traffic contexts and must
  promptly destroy obsolete handshake state. Cipher destruction clears the
  allocated state, including the selected backend's session key schedule.
- DH/HKDF/temporary key stack buffers have explicit cleanup sites. This source
  map does not prove every optimized stack/register copy is erased, stack
  exhaustion is handled, or callee scratch has been measured. Heap fault
  injection cannot establish those claims.

The nm inventory is a complementary check of unresolved allocator symbols in
the selected built Noise archive, not proof about future endpoint hot paths or
all dynamic runtime-library internals.
