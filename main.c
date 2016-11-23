#include "libwshandshake.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main()
{
    char output[29] = {};
    for (int i = 0; i < 1000000; i++) {
        lwsh_generate("dGhlIHNhbXBsZSBub25jZQ==", output);
    }
    printf("%s\n", output);
}
