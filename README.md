# libwshandshake
This repo tracks the development of a cross-platform standard C++ WebSocket handshake implementation. You want to get from the client's 24-byte base64 token to the server's 28 byte base64 response:

```c++
#include "libwshandshake.hpp"
#include <iostream>

int main()
{
    char output[29] = {};
    WebSocketHandshake::generate("dGhlIHNhbXBsZSBub25jZQ==", output);
    std::cout << output << std::endl;
}
```

this would output: `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` which of course is the response to send. Performance has been an important factor in the development and should be on par with the equivalent OpenSSL alternative. One million handshakes can be performed in about 200 milliseconds on a modern CPU.
