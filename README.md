#  Branca Tokens for Python

Authenticated and encrypted API tokens using modern crypto.


[![Latest Version](https://img.shields.io/pypi/v/pybranca.svg?style=flat-square)](https://pypi.org/project/pybranca/)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/tuupola/branca-python/master.svg?style=flat-square)](https://travis-ci.org/tuupola/branca-python)
[![Coverage](https://img.shields.io/codecov/c/github/tuupola/branca-python.svg?style=flat-square)](https://codecov.io/github/tuupola/branca-python)

## What?

[Branca](https://branca.io/) is a secure easy to use token format which makes it hard to shoot yourself in the foot. It uses IETF XChaCha20-Poly1305 AEAD symmetric encryption to create encrypted and tamperproof tokens. Payload itself is an arbitrary sequence of bytes. You can use for example a JSON object, plain text string or even binary data serialized by [MessagePack](http://msgpack.org/) or [Protocol Buffers](https://developers.google.com/protocol-buffers/).

Although not a design goal, it is possible to use [Branca as an alternative to JWT](https://appelsiini.net/2017/branca-alternative-to-jwt/).

## Install

Install the library using pip. Note that you also must have [libsodium](https://download.libsodium.org/doc/) installed.

```
$ brew install libsodium
$ pip install pybranca
```

## Usage

The payload of the token can be anything, like a simple string.

```python
from branca import Branca

branca = Branca(key="supersecretkeyyoushouldnotcommit")

token = branca.encode("Hello world!")
payload = branca.decode(token)

print(token)
print(payload)

# 87xqn4ACMhqDZvoNuO0pXykuDlCwRz4Vg7LS3klfHpTiOUw1ramOqfWoaA6bvsGwOQ49MDFOERU0T
# b'Hello world!'
```

For more complicated data structures JSON is an usual choice.

```python
import json
from branca import Branca

branca = Branca(key="supersecretkeyyoushouldnotcommit")

string = json.dumps({
    "user" : "someone@example.com",
    "scope" : ["read", "write", "delete"]
})

token = branca.encode(string)
payload = branca.decode(token)

print(token)
print(payload)
print(json.loads(payload))

# 1SlQocC4osLlwob7xQEAXNhyowLZSA3pFpXqYeQxZI6fTg7BEv2ulHBddRYq8JjoMsnObiPbucoK2 \
# CEd4daAjTJE5HJOL2jEOY2rjiJQ9b1joKruxOVVR1zzSF65lRPLp4uExxHGKDaWceJtdrSmqBHFfk
# b'{"user": "someone@example.com", "scope": ["read", "write", "delete"]}'
# {'user': 'someone@example.com', 'scope': ['read', 'write', 'delete']}
```

By using [MessagePack](https://msgpack.org/) you can have more compact tokens.

```python
import msgpack
from branca import Branca

branca = Branca(key="supersecretkeyyoushouldnotcommit")

packed = msgpack.dumps({
    "user" : "someone@example.com",
    "scope" : ["read", "write", "delete"]
})

token = branca.encode(packed)
payload = branca.decode(token)

print(token)
print(payload)
print(msgpack.loads(payload, raw=False))

# gMaGwZR19MOIaWQKtSIe9Hy2V0XENkVPsTG2f3hdoUOmdcPizoEJoga6p8Fi0z18SocXTLC7dOl5P \
# fDaRa3udIfeyd6KqLCOZ89ZpEZ15xiLGk5FFywrMhlPOCLdIpoW7
# b'\x82\xa4user\xb3someone@example.com\xa5scope\x93\xa4read\xa5write\xa6delete'
# {'user': 'someone@example.com', 'scope': ['read', 'write', 'delete']}
```

## License

The MIT License (MIT). Please see [License File](LICENSE.txt) for more information.