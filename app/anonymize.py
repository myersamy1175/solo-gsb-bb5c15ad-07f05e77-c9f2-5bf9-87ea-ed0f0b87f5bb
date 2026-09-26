"""Prefix-preserving keyed anonymization of bare IPv4/IPv6 addresses and CIDRs.

The address bits are processed in network bit order (most-significant bit
first).  For the bit at position ``i`` of an address (``i`` is 0-based) the
HMAC message is the concatenation of:

1. the address-family byte — ``4`` for IPv4, ``6`` for IPv6 (the IP version
   number);
2. the current bit-position byte — ``i`` as one byte (0..31 for IPv4,
   0..127 for IPv6);
3. the original bits strictly before position ``i`` packed back into the
   family width (4 bytes for IPv4, 16 for IPv6) and right-padded with zero
   bits — i.e. the address with bit ``i`` and every later bit cleared.

The most-significant bit of the first HMAC-SHA256 digest byte is XORed onto
the current original bit to produce the anonymized bit.  Because the pad bit
at position ``i`` depends only on the original prefix preceding it, the
transform is a prefix-preserving permutation of each address family:

* the mapping is **stable** for a fixed key (HMAC is deterministic);
* it is **one-to-one** — the original bits can be recovered left to right,
  since each pad bit is a function of already-recovered original prefix bits;
* the **longest common prefix length of any two addresses is unchanged**:
  equal original prefix bits share the same pad bit and stay equal, and the
  first differing bit meets the same pad bit on both sides and stays
  different.

Strict CIDRs are anonymized by transforming their (host-bit-free) network
address and clearing the host bits again at the original prefix length, so
the result is the canonical image of the whole prefix.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Callable, Sequence

from app.policy import Address, Network, parse_address, parse_network

#: First HMAC message byte: the IP version number identifies the family.
_FAMILY_TAG: dict[type, int] = {
    ipaddress.IPv4Address: 4,
    ipaddress.IPv6Address: 6,
}

#: Address width in bits per family tag.
_FAMILY_WIDTH: dict[int, int] = {4: 32, 6: 128}

#: Exact hexadecimal digits accepted in ``key_hex`` (``bytes.fromhex`` would
#: otherwise tolerate embedded whitespace).
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def parse_key_hex(value: object) -> bytes:
    """Parse the 64-hex-character (32-byte) HMAC key.

    Any other input (wrong type, wrong length or a non-hex character) raises
    :class:`ValueError`, which the Pydantic schema maps to an HTTP 422.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"key_hex must be a string, got {type(value).__name__}"
        )
    text = value.strip()
    if len(text) != 64 or any(char not in _HEX_DIGITS for char in text):
        raise ValueError(
            "key_hex must be exactly 64 hexadecimal characters "
            "(32 bytes / 256 bits)"
        )
    return bytes.fromhex(text)


def _hmac_digest_bit(
    key: bytes,
    tag: int,
    position: int,
    prefix: int,
    width: int,
) -> int:
    """Return the keyed pad bit for one address position.

    ``prefix`` holds the original bits strictly before ``position`` in their
    high-order places with zero padding to the family width.  The pad bit is
    the most-significant bit of the first HMAC-SHA256 digest byte.
    """
    message = bytes([tag, position]) + prefix.to_bytes(width // 8, "big")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return digest[0] >> 7


def _anonymize_int(
    value: int,
    width: int,
    tag: int,
    digest_bit: Callable[[int, int, int], int],
) -> int:
    """Anonymize one packed address integer bit by bit in network order.

    ``digest_bit(tag, position, prefix)`` supplies the keyed pad bit for a
    position; injecting it lets the caller cache repeated prefixes across a
    batch of addresses.  ``prefix`` is the address with ``position`` and all
    later bits cleared.
    """
    result = 0
    for position in range(width):
        shift = width - 1 - position
        # Bits strictly left of `position`, shifted back to their places:
        # bit `position` and every bit to its right read as zero.
        prefix = (value >> (shift + 1)) << (shift + 1)
        original_bit = (value >> shift) & 1
        result |= (original_bit ^ digest_bit(tag, position, prefix)) << shift
    return result


def anonymize(
    key_hex: str,
    address_raw: Sequence[str],
    cidr_raw: Sequence[str],
) -> dict:
    """Anonymize bare addresses and strict CIDRs under one key.

    Inputs are assumed validated already (e.g. by the Pydantic schema):
    ``key_hex`` is 64 hex characters, every address is a bare IPv4/IPv6
    address and every CIDR parses strictly (host bits zero).  Results come
    back in two lists, each keeping its input order.
    """
    key = parse_key_hex(key_hex)

    # Addresses in one family frequently share a leading prefix, and the pad
    # bit of every position before their first differing bit is identical;
    # memoize per (family, position, original prefix) within this one call.
    # The cache deliberately does not outlive the request so key material is
    # never retained at module scope.
    digest_cache: dict[tuple[int, int, int], int] = {}

    def digest_bit(tag: int, position: int, prefix: int) -> int:
        cache_key = (tag, position, prefix)
        bit = digest_cache.get(cache_key)
        if bit is None:
            bit = _hmac_digest_bit(
                key, tag, position, prefix, _FAMILY_WIDTH[tag]
            )
            digest_cache[cache_key] = bit
        return bit

    anonymized_addresses: list[str] = []
    for item in address_raw:
        address: Address = parse_address(item)
        tag = _FAMILY_TAG[type(address)]
        result = _anonymize_int(
            int(address), _FAMILY_WIDTH[tag], tag, digest_bit
        )
        anonymized_addresses.append(str(type(address)(result)))

    anonymized_cidrs: list[str] = []
    for item in cidr_raw:
        network: Network = parse_network(item)
        tag = network.version
        width = _FAMILY_WIDTH[tag]
        # A strict network already has its host bits zero; transform the
        # network address and re-clear the host bits at the original prefix
        # length so the result is the canonical image prefix.
        result = _anonymize_int(
            int(network.network_address), width, tag, digest_bit
        )
        image = type(network)((result, network.prefixlen), strict=False)
        anonymized_cidrs.append(str(image))

    return {
        "addresses": anonymized_addresses,
        "cidrs": anonymized_cidrs,
    }
