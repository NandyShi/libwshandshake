# libwshandshake
This repository holds a minimal header-only C++ implementation of the RFC6455 (WebSocket protocol 13) handshake algorithm. When a WebSocket client requests an upgrade over HTTP/1.1 it passes a 24 byte base64 encoded string to be processed in a particular way according to the specification. With libwshandshake this entire procedure becomes very simple as displayed below:

```c++
#include "libwshandshake.hpp"
#include <iostream>

int main()
{
    // output is 28 bytes in base64 encoding, but we want an extra 0 to end the string a la C
    char output[29] = {};
    WebSocketHandshake::generate("dGhlIHNhbXBsZSBub25jZQ==", output);
    std::cout << output << std::endl;
}
```

This would output: `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` which of course is the response to send. Performance has been an important factor of the development process and should be on par with the equivalent OpenSSL based alternatives. One million handshakes can be performed in about 200 milliseconds on a modern CPU.
