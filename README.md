# libwshandshake
This repo tracks the development of a cross-platform standard C WebSocket handshake implementation. You want to get from the client's 20-byte base64 token to the server's 28 byte base64 response:

```c
#include "libwshandshake.h"
#include <stdio.h>
#include <string.h>

int main()
{
    char output[29] = {};
    lwsh_generate("dGhlIHNhbXBsZSBub25jZQ==", output);
    printf("%s\n", output);
}
```

this would output: `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` which of course is the response to send. Currently the performance is 4x as bad compared to OpenSSL.
