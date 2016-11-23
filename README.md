# libwshandshake
This repo tracks the development of a cross-platform standard C WebSocket handshake implementation. You want to get from the client's 20-byte base64 token to the server's 28 byte base64 response:

```c++
#include "libwshandshake.h"
#include <iostream>

int main() {
    char output[28];
    WebSocketHandshakeHash("dGhlIHNhbXBsZSBub25jZQ==", output);
    std::cout << std::string(output, 28) << std::endl;
}
```

this would output: `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` which of course is the response to send. Currently the performance is 4x as bad compared to OpenSSL.
