# Crypto

Small, fast, header only, zero dependency cryptographic library written in C++2a.

## Cryptographic hash functions

Cryptographic Hash Functions (CHFs) are a family of algorithms that take an input (or message) and produce a fixed-size output, known as the hash value or digest. This process is a one-way function, meaning it is computationally infeasible to reverse the hash value to obtain the original input. Additionally, small changes in the input will result in significantly different hash values.

### Algorithms

|Class                    |Word bits|Size bits|Block bits|Rounds|State bits|Output bits|
|-------------------------|--------:|--------:|---------:|-----:|---------:|----------:|
|[MD4](md4.hh)            |       32|       64|       512|     3|       128|        128|
|[MD5](md5.hh)            |       32|       64|       512|    64|       128|        128|
|[RMD<128>](rmd.hh)       |       32|       64|       512|    64|       128|        128|
|[RMD<160>](rmd.hh)       |       32|       64|       512|    80|       160|        160|
|[RMD<256>](rmd.hh)       |       32|       64|       512|    64|       256|        256|
|[RMD<320>](rmd.hh)       |       32|       64|       512|    80|       320|        320|
|[SHA1](sha1.hh)          |       32|       64|       512|    80|       160|        160|
|[SHA2<256,224>](sha2.hh) |       32|       64|       512|    64|       256|        224|
|[SHA2<256,256>](sha2.hh) |       32|       64|       512|    64|       256|        256|
|[SHA2<512,224>](sha2.hh) |       64|      128|      1024|    80|       512|        224|
|[SHA2<512,256>](sha2.hh) |       64|      128|      1024|    80|       512|        256|
|[SHA2<512,384>](sha2.hh) |       64|      128|      1024|    80|       512|        384|
|[SHA2<512,512>](sha2.hh) |       64|      128|      1024|    80|       512|        512|


### Examples

Double hashing the contents of a container holding trivially copyable objects with the help of `SHA2<256>` and  `RMD<160>`. Note that `rmd<160>(message)` is an alias for `RMD<160>().update(message).digest()`.

```cpp
#include <crypto/rmd.h>
#include <crypto/sha2.h>

using namespace crypto;

auto
hash(const auto &trivially_copyable_objects) {

    auto hasher = SHA2<256>();

    for (const auto &entry: trivially_copyable_objects) {
        hasher.update(entry);
    }

    return rmd<160>(hasher.update("secret").digest());
}
```

## Message authentication codes

Message Authentication Codes (MACs) are cryptographic mechanisms used to ensure the integrity and authenticity of a message or data transmission. They provide a way to verify that a message has not been tampered with during transmission and that it originates from a trusted source.

### Algorithms

Only the hash-based message authentication code ([HMAC](hmac.hh)) is supported at the moment.

### Examples

Double hashing the contents of a container holding trivially copyable objects with the help of `HMAC`, `SHA2<256>` and  `RMD<160>`. Note that `hmac<RMD<160>>(secret, message)` is an alias for `HMAC<RMD<160>>(secret).update(message).digest()`.

```cpp
#include <crypto/rmd.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>

using namespace crypto;

auto
hash(const auto &trivially_copyable_objects) {

    auto hasher = HMAC<SHA2<256>>("secret 1");

    for (const auto &entry: trivially_copyable_objects) {
        hasher.update(entry);
    }

    return hmac<RMD<160>>("secret 2", hasher.digest());
}
```


## Installation

Download the sources to the folder of choice and include the desired headers.


## Contributing

Feature requests, bug reports and success stories are most welcome.


## Copyright

Copyright 2018 Quasis - The MIT License
