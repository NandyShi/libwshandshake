#include "libwshandshake.hpp"
#include <iostream>

int main()
{
    char output[29] = {};
    for (int i = 0; i < 1000000; i++) {
        WebSocketHandshake::generate("dGhlIHNhbXBsZSBub25jZQ==", output);
    }
    std::cout << output << std::endl;
}
