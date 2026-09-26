/* Toolchain/runner check only; no protocol or crypto conformance is implied. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

_Static_assert(CHAR_BIT == 8, "DMP requires eight-bit octets");
_Static_assert(sizeof(uint32_t) == 4, "DMP requires uint32_t");
_Static_assert(sizeof(uint64_t) == 8, "DMP requires uint64_t");

int main(void)
{
    printf("host scaffold: C11, octets=%d, pointer_bits=%zu, size_t_bits=%zu\n",
           CHAR_BIT, sizeof(void *) * CHAR_BIT, sizeof(size_t) * CHAR_BIT);
    puts("No provider, endpoint, target-memory or conformance claim.");
    return 0;
}
