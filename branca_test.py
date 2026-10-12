# Copyright (c) 2018-2021 Mika Tuupola
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of  this software and associated documentation files (the "Software"), to
# deal in  the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copied of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from branca import Branca
from binascii import unhexlify, hexlify
import os
import pytest
import struct
import xchacha20poly1305

#
# Decoding vectors
#

# Test vector 8
def test_decode_hello_world_with_zero_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)
    token = "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 0

# Test vector 9
def test_decode_hello_world_with_max_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)
    token = "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 4294967295

# Test vector 10
def test_decode_hello_world_with_nov27_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 123206400

# Test vector 11
def test_decode_eight_nul_bytes_with_zero_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 0

# Test vector 12
def test_decode_eight_nul_bytes_with_max_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "1jrx6DUu5q06oxykef2e2ZMyTcDRTQot9ZnwgifUtzAphGtjsxfbxXNhQyBEOGtpbkBgvIQx"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 4294967295

# Test vector 13
def test_decode_eight_nul_bytes_with_nov27_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "1jJDJOEjuwVb9Csz1Ypw1KBWSkr0YDpeBeJN6NzJWx1VgPLmcBhu2SbkpQ9JjZ3nfUf7Aytp"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 123206400

# Test vector 14
def test_decode_empty_payload():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

    assert branca.decode(token) == b""
    assert branca.timestamp(token) == 0

# Test vector 15
def test_decode_non_utf8_payload():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "K9u6d0zjXp8RXNUGDyXAsB9AtPo60CD3xxQ2ulL8aQoTzXbvockRff0y1eXoHm"

    assert branca.decode(token) == b"\x80"
    assert branca.timestamp(token) == 123206400

# Test vector 16
def test_should_throw_with_wrong_version():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 17
def test_should_throw_with_invalid_base62():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT_"

    with pytest.raises(ValueError):
        branca.decode(token)

# Test vector 18
def test_should_throw_with_modified_version():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "89mvl3S0BE0UCMIY94xxIux4eg1w5oXrhvCEXrDAjusSbO0Yk7AU6FjjTnbTWTqogLfNPJLzecHVb"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 19
def test_should_throw_with_modified_nonce():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH233SUysT7fQ711EWd9BXpwOjB72ng3ZLnjWFrmOqVy49Bv93b78JU5331LbcY0EEzhLfpmSx"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 20
def test_should_throw_with_modified_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "870g1RCk4lW1YInhaU3TP8u2hGtfol16ettLcTOSoA0JIpjCaQRW7tQeP6dQmTvFIB2s6wL5deMXr"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 21
def test_should_throw_with_modified_ciphertext():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5Qw6Jpo96myliI3hHD7VbKZBYh"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 22
def test_should_throw_with_modified_tag():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trk0"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 23
def test_should_throw_with_wrong_key():
    key = unhexlify("77726f6e677365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)
    token = "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 24
def test_should_throw_with_invalid_key():
    with pytest.raises(ValueError):
        key = unhexlify("746f6f73686f72746b6579")
        branca = Branca(key)

#
# Encoding vectors
#

# Test vector 0
def test_encode_hello_world_with_zero_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=0)

    assert token == "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

# Test vector 1
def test_encode_hello_world_with_max_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=4294967295)

    assert token == "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr"

# Test vector 2
def test_encode_hello_world_with_november_27_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=123206400)

    assert token == "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

# Test vector 3
def test_encode_eight_nul_bytes_with_zero_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=0)

    assert token == "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1"

# Test vector 4
def test_encode_eight_nul_bytes_with_max_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=4294967295)

    assert token == "1jrx6DUu5q06oxykef2e2ZMyTcDRTQot9ZnwgifUtzAphGtjsxfbxXNhQyBEOGtpbkBgvIQx"

# Test vector 5
def test_encode_eight_nul_bytes_with_november_27_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=123206400)

    assert token == "1jJDJOEjuwVb9Csz1Ypw1KBWSkr0YDpeBeJN6NzJWx1VgPLmcBhu2SbkpQ9JjZ3nfUf7Aytp"

# Test vector 6
def test_encode_empty_payload():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"", timestamp=0)

    assert token == "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

# Test vector 7
def test_encode_non_utf8_payload():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"", timestamp=0)

    assert token == "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

#
# Implementation specific tests
#

def test_should_throw_when_expired():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode(b"Hello world!", timestamp=123206400)

    with pytest.raises(RuntimeError):
        branca.decode(token, 3600)

def test_should_get_timestamp():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "1jJDJOEeG2FutA8g7NAOHK4Mh5RIE8jtbXd63uYbrFDSR06dtQl9o2gZYhBa36nZHXVfiGFz"

    assert branca.timestamp(token) == 123206400

def test_should_allow_bytes_key():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 123206400

def test_should_allow_hex_string_key():
    branca = Branca(key="73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")

    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 123206400

@pytest.mark.parametrize("size", [0, 1, 31, 64, 255, 1024, 2048])
def test_should_be_compatible_with_pybase62_tokens(size):
    base62 = pytest.importorskip("base62")
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)
    nonce = xchacha20poly1305.generate_nonce()
    header = struct.pack(">BL", Branca.VERSION, 123206400) + nonce
    payload = os.urandom(size)
    ciphertext = xchacha20poly1305.crypto_aead_xchacha20poly1305_ietf_encrypt(payload, header, nonce, key)
    pybase62_token = base62.encodebytes(header + ciphertext)

    assert branca.decode(pybase62_token) == payload
    assert branca.timestamp(pybase62_token) == 123206400

    branca._nonce = nonce
    assert branca.encode(payload, timestamp=123206400) == pybase62_token

def test_should_be_compatible_with_v0_5_1_token():
    key = unhexlify("73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    branca = Branca(key)
    payload = bytes(range(256)) * 4
    token = (
        "2U5t2GpPY1Np2dnRG4FtwS2czXEGiJuQl7R6XcInD9RyAbI7NG2eJKj5EJsf3hOCqiUYfpZECCRFwfd2tv0V0sagxUa7WkBeiWKQ"
        "DnYx09xIOkhEQFl8alrvQOiiZcI1Y0PIuhc94jMspSLz4rmcC2hKrTkqQs4fiuiQQVHEZYG96kHaiG29u671hnYsYrLapwvd41GZ"
        "99LBcVcPl9uO5N7AoPj3DaSksUhH52ivJWsDKEMsdbc5qYM07a26mCkoIBBqnOeNk90uZRCTl4q4ZQPjvrB3u7BdajRBJck9ivl0"
        "sesU493DlO6SIRHbP7nTDzlTvxHUxevfGY8oONNzlqnb9ZRp4AqF8YSbwy0va5vOGrbIB5F6z46erPkcLx27capqrWT19MwG7dJd"
        "hxJVyHmK4ZHbiWU3mKG5acq2A096IuYGZOyq685rQS3bratZjxIx6WvQAe5UrIjCTeuSsIQxyRuYa6DGOgRaXIoHP8uLWB9R7Yb3"
        "tJwDnehHadiGb1dcZ8mFyUTaY4x21iXxYzy9fSD07NeYOOqjSg81MKbqOCoMCBiq4x51X8UVkWA8yZY1s4sMLhviDGnzChPMvYHf"
        "5zk5mhTOzGdp6owoXfOX72wnWqubju22h2ouYIfe6a0q1vSiK7q5rX8onBMLrPHyQbNzLAgsqxXZb4Uf8ze69FQjlHAMhxGNSaXy"
        "MaNpvqplkv9U2wDZ8pfsb6B0gqlZ6KDsEENZ9cvgmw7ore3OnZhcxuLYwWEqhfK5CImFkLA6GnHoH9rKYHTRMCHfj9whVSnx0n4E"
        "HERBKG5P5P7LbsgNOxbPKJHSrEGWLCeNWW18rH7XeL107Vqc7MIqBqxUcRYZAfRAKkkC89UBTRBJAL57F2mFyKYyDzUghzzoqmEs"
        "glz3z0Kn2BZ36drRewJ7idGRLgttSo9EZRcdggBj9WZho7yT8cJpKHiDI2VgPgom5ztUMx3Gc8Pk681XiXK5HcB1laRLZlZmeTl1"
        "Mic2V2EMh9mOZbDPDTDy6dghB2qPKjX1xjGcctVZR56pd1KAKO7yIVRWSoXFUsXfbD1Db6RMsOU7P7Ovu3mlE7wT3VQUfND6AKPc"
        "bn4zLvyG4QTAVtk4hT5PQDJhYdtWSYQNRN362Wcj2zgsz6jaeUbkTj9BluVe4TRMcxeDRMDo6F1LLsoNWh4lQpsYAI2sy0RJoSaU"
        "eq16pG6CJhguPurWGjMes1ryzh658QpazoPnBA6PeGivYW9pCdQyRTC0FiR3PWuN4fUSJGqsS7IJ6ZIf32SzIAdPgJXVhilWm7Cl"
        "LAbxrwdepJn80e7Sl7gdqjv8FCkJ7P25J5ryanzkYR23zNbLU2r7SGyODFS8Gy83VM39H6q2tK98WC7QikVfVIpnFW39hARD9rUW"
        "RhY3x2pN323zvogK239qozyM0sDmqUbPbvtjr"
    )

    assert branca.decode(token) == payload
    assert branca.timestamp(token) == 123206400

    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    assert branca.encode(payload, timestamp=123206400) == token

def test_should_round_trip_large_payload():
    branca = Branca(key="73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")
    payload = os.urandom(1000000)

    assert branca.decode(branca.encode(payload)) == payload

@pytest.mark.parametrize("token", [
    "",
    "0875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT",
    "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsC TOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT",
    " 875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT",
    "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT\n",
    "-875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT",
])
def test_should_throw_with_non_canonical_base62(token):
    branca = Branca(key="73757065727365637265746b6579796f7573686f756c646e6f74636f6d6d6974")

    with pytest.raises(ValueError):
        branca.decode(token)

