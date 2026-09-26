/* Test guard: selected checked provider must not call legacy void RNG APIs. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
void __wrap_randombytes_stir(void)
{
    fputs("Unexpected legacy randombytes_stir in checked provider\n", stderr);
    _Exit(91);
}
void __wrap_randombytes_buf(void *buffer, size_t size)
{
    (void)buffer;
    (void)size;
    fputs("Unexpected legacy randombytes_buf in checked provider\n", stderr);
    _Exit(92);
}
