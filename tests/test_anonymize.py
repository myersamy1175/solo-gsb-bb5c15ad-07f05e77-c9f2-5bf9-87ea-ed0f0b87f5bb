"""Unit + property tests for prefix-preserving anonymization (stdlib only)."""

from __future__ import annotations

import ipaddress
import random

import pytest

from app.anonymize import (
    _anonymize_int,
    _FAMILY_TAG,
    _FAMILY_WIDTH,
    _hmac_digest_bit,
    anonymize,
    parse_key_hex,
)

KEY = "0123456789abcdef" * 4


def _bit_function(key: bytes):
    """Straight (uncached) per-position pad bit over HMAC-SHA256."""

    def digest_bit(tag: int, position: int, prefix: int) -> int:
        return _hmac_digest_bit(
            key, tag, position, prefix, _FAMILY_WIDTH[tag]
        )

    return digest_bit


def _lcp(left: int, right: int, width: int) -> int:
    """Longest common prefix length of two packed address integers."""
    differing = left ^ right
    for position in range(width):
        if (differing >> (width - 1 - position)) & 1:
            return position
    return width


def test_known_answer_vectors():
    # Pins the exact message layout: family byte, position byte, original
    # prefix right-padded with zero bits; pad bit = MSB of digest byte 0.
    assert anonymize(KEY, ["192.168.0.1"], []) == {
        "addresses": ["236.222.104.188"], "cidrs": [],
    }
    assert anonymize(KEY, ["2001:db8::1"], []) == {
        "addresses": ["d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a"],
        "cidrs": [],
    }
    assert anonymize(KEY, [], ["10.0.0.0/8", "192.168.0.0/24",
                               "2001:db8::/32"]) == {
        "addresses": [],
        "cidrs": ["77.0.0.0/8", "236.222.104.0/24", "d5af:46c8::/32"],
    }
    # A different key (all-zero) gives a different image.
    assert anonymize("00" * 32, ["10.0.0.1"], [])["addresses"] == [
        "125.66.150.228"
    ]


def test_mapping_is_stable_under_one_key():
    first = anonymize(KEY, ["10.0.0.1", "2001:db8::1"], ["10.0.0.0/24"])
    second = anonymize(KEY, ["10.0.0.1", "2001:db8::1"], ["10.0.0.0/24"])
    assert first == second


def test_distinct_addresses_map_to_distinct_addresses():
    inputs = [
        "10.0.0.1", "10.0.0.2", "192.168.0.1", "127.0.0.1",
        "2001:db8::1", "2001:db8::2", "::1", "fe80::1",
    ]
    result = anonymize(KEY, inputs, [])["addresses"]
    assert len(set(result)) == len(inputs)


def test_duplicate_inputs_map_to_identical_outputs():
    result = anonymize(KEY, ["10.0.0.1", "10.0.0.1"], [])["addresses"]
    assert result[0] == result[1]


def test_result_lists_follow_input_order():
    addresses = ["2001:db8::1", "10.0.0.1", "192.168.0.5", "10.0.0.2"]
    cidrs = ["2001:db8::/32", "10.0.0.0/24", "192.168.0.0/16"]
    one = anonymize(KEY, addresses, cidrs)
    shuffled = anonymize(KEY, list(reversed(addresses)), list(reversed(cidrs)))
    assert one["addresses"] == list(reversed(shuffled["addresses"]))
    assert one["cidrs"] == list(reversed(shuffled["cidrs"]))


def test_ipv4_subtree_maps_bijectively_onto_its_image():
    # The 256 addresses of one /24 must cover the image /24 exactly: prefix
    # preservation keeps every image inside the image block, and injectivity
    # (distinct addresses share at most 31 prefix bits) makes them distinct.
    network = ipaddress.ip_network("10.0.0.0/24")
    members = [str(network.network_address + offset) for offset in range(256)]
    images = anonymize(KEY, members, [])["addresses"]
    image_network = ipaddress.ip_network(
        anonymize(KEY, [], ["10.0.0.0/24"])["cidrs"][0]
    )
    assert len(set(images)) == 256
    assert all(
        ipaddress.ip_address(value) in image_network for value in images
    )
    assert {
        int(ipaddress.ip_address(value))
        - int(image_network.network_address)
        for value in images
    } == set(range(256))


def test_ipv6_subtree_maps_bijectively_onto_its_image():
    network = ipaddress.ip_network("2001:db8::/120")
    members = [str(network.network_address + offset) for offset in range(256)]
    images = anonymize(KEY, members, [])["addresses"]
    image_network = ipaddress.ip_network(
        anonymize(KEY, [], ["2001:db8::/120"])["cidrs"][0]
    )
    assert len(set(images)) == 256
    assert all(
        ipaddress.ip_address(value) in image_network for value in images
    )


@pytest.mark.parametrize("family", [ipaddress.IPv4Address, ipaddress.IPv6Address])
def test_mapping_is_invertible_and_prefix_preserving(family):
    key = parse_key_hex(KEY)
    tag = _FAMILY_TAG[family]
    width = _FAMILY_WIDTH[tag]
    digest_bit = _bit_function(key)
    random.seed(7 if width == 32 else 11)

    def invert(image: int) -> int:
        # Recover original bits left to right: each pad bit depends only on
        # already-recovered original prefix bits.
        original = 0
        for position in range(width):
            shift = width - 1 - position
            prefix = (original >> (shift + 1)) << (shift + 1)
            pad = digest_bit(tag, position, prefix)
            original |= (((image >> shift) & 1) ^ pad) << shift
        return original

    samples = [random.getrandbits(width) for _ in range(400)]
    images = {
        value: _anonymize_int(value, width, tag, digest_bit)
        for value in samples
    }
    for value, image in images.items():
        assert invert(image) == value
    pairs = list(zip(samples[::2], samples[1::2], strict=True))
    for left, right in pairs:
        assert _lcp(left, right, width) == _lcp(
            images[left], images[right], width
        )


def test_cidr_image_has_zero_host_bits_and_keeps_prefix_length():
    result = anonymize(
        KEY, [], ["10.0.0.128/25", "192.168.0.0/16", "2001:db8::/48"]
    )["cidrs"]
    for text in result:
        network = ipaddress.ip_network(text, strict=True)
        assert int(network.network_address) & (
            (1 << (network.max_prefixlen - network.prefixlen)) - 1
        ) == 0
    assert [ipaddress.ip_network(text).prefixlen for text in result] == [
        25, 16, 48
    ]


def test_members_of_a_cidr_anonymize_inside_its_image():
    key = parse_key_hex(KEY)
    for cidr in ["10.0.0.0/26", "192.168.1.0/24", "2001:db8::/126"]:
        network = ipaddress.ip_network(cidr)
        image_text = anonymize(KEY, [], [cidr])["cidrs"][0]
        image_network = ipaddress.ip_network(image_text)
        members = [
            str(network.network_address + offset)
            for offset in (0, 1, 2, network.num_addresses - 1)
        ]
        for value in anonymize(KEY, members, [])["addresses"]:
            assert ipaddress.ip_address(value) in image_network


def test_bare_address_in_cidr_list_is_a_host_prefix():
    # Mirrors parse_network's behavior on the other endpoints.
    assert anonymize(KEY, [], ["10.0.0.1"])["cidrs"][0].endswith("/32")
    assert anonymize(KEY, [], ["2001:db8::1"])["cidrs"][0].endswith("/128")


def test_invalid_key_raises_value_error():
    for bad in ["", "abc", "00" * 31, "ff" * 33, "g" * 64,
                "00 " + "00" * 31, "0x" + "00" * 32, 32, None]:
        with pytest.raises(ValueError):
            parse_key_hex(bad)


def test_surrounding_whitespace_in_key_is_tolerated():
    assert parse_key_hex(f"  {KEY}\n") == bytes.fromhex(KEY)


def test_invalid_addresses_and_cidrs_raise_value_error():
    with pytest.raises(ValueError):
        anonymize(KEY, ["10.0.0.1/24"], [])
    with pytest.raises(ValueError):
        anonymize(KEY, ["bogus"], [])
    with pytest.raises(ValueError):
        anonymize(KEY, [], ["10.0.0.1/24"])
    with pytest.raises(ValueError):
        anonymize(KEY, [], ["not-a-cidr"])


def test_different_keys_give_different_mappings():
    # The probability of an accidental collision per bit is 1/2; matching on
    # the whole address would happen with probability 2^-32 / 2^-128.
    left = anonymize(KEY, ["10.0.0.1", "2001:db8::1"], [])["addresses"]
    right = anonymize("ff" * 32, ["10.0.0.1", "2001:db8::1"], [])[
        "addresses"
    ]
    assert left != right
