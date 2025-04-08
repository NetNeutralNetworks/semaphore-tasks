#!/usr/bin/env python

import base64
import logging
import os
import random
import re
import sys
import threading
from functools import lru_cache
from typing import List, Optional, Tuple

import passlib.crypto
import passlib.hash
import scrypt

BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

LOCK = threading.Lock()


"""
A python port of https://metacpan.org/pod/Crypt::Juniper

Original Author: Kevin Brintnall
Ported by: Zach Bray
"""


MAGIC = "$9$"
EXTRA = {}
ENCODING = [
    [1, 4, 32],
    [1, 16, 32],
    [1, 8, 32],
    [1, 64],
    [1, 32],
    [1, 4, 16, 128],
    [1, 32, 64],
]

# letter families to encrypt with
FAMILY = [
    "QzF3n6/9CAtpu0O",
    "B1IREhcSyrleKvMW8LXx",
    "7N-dVbwsY2g4oaJZGUDj",
    "iHkq.mPf5T",
]
EXTRA = {char: 3 - i for i, fam in enumerate(FAMILY) for char in fam}

# builds regex to match valid encrypted string
letters = MAGIC + "([" + "".join(FAMILY) + "]{4,})"
letters = re.sub(r"([-|/|$])", r"\\\1", letters)
VALID = r"^" + letters + "$"

# forward and reverse dicts
NUM_ALPHA = [char for char in "".join(FAMILY)]
ALPHA_NUM = {NUM_ALPHA[i]: i for i, c in enumerate(NUM_ALPHA)}


def junos_decrypt(crypt):
    m = re.match(VALID, crypt)

    if not m:
        print("invalid crypt string")
        exit(1)

    chars = m.group(1)
    chars, first = _junos_nibble(chars, 1)
    chars, _ = _junos_nibble(chars, EXTRA[first])

    prev = first
    decrypt = ""

    while chars:
        decode = ENCODING[len(decrypt) % len(ENCODING)]
        chars, nibble = _junos_nibble(chars, len(decode))

        gaps = []
        for nib in nibble:
            dist = (ALPHA_NUM[nib] - ALPHA_NUM[prev]) % len(NUM_ALPHA) - 1
            gaps.append(dist)
            prev = nib

        decrypt += _junos_gap_decode(gaps, decode)
    return decrypt


def _junos_nibble(chars, length):
    nib = chars[:length]
    chars = chars[length:]
    return chars, nib


def _junos_gap_decode(gaps, decode):
    num = 0
    for i in range(len(gaps)):
        num += gaps[i] * decode[i]

    return chr(num % 256)


# encrypts <secret> for junipers $9$ format
# allows use of seed for idempotent secrets
def junos_encrypt(secret, seed=False):
    if seed:
        random.seed(seed)

    salt = _junos_random_salt(1)
    rand = _junos_random_salt(EXTRA[salt])

    pos = 0
    prev = salt
    crypt = MAGIC + salt + rand

    for char in secret:
        encode = ENCODING[pos % len(ENCODING)]
        crypt += _junos_gap_encode(char, prev, encode)
        prev = crypt[-1]
        pos += 1

    return crypt


# returns number of characters from the alphabet
def _junos_random_salt(length):
    salt = ""
    for i in range(length):
        salt += NUM_ALPHA[random.randrange(len(NUM_ALPHA))]
    return salt


# encode plain text character with a series of gaps
def _junos_gap_encode(char, prev, encode):
    crypt = ""
    val = ord(char)
    gaps = []

    for enc in encode[::-1]:
        gaps.insert(0, val // enc)
        val %= enc

    for gap in gaps:
        gap += ALPHA_NUM[prev] + 1
        c = prev = NUM_ALPHA[gap % len(NUM_ALPHA)]
        crypt += c

    return crypt


### Stolen from: https://github.com/BrettVerney/ciscoPWDhasher/
_STD_B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_CISCO_B64CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B64TABLE = str.maketrans(_STD_B64CHARS, _CISCO_B64CHARS)


### Stolen from: https://github.com/BrettVerney/ciscoPWDhasher/
class InvalidPassword(Exception):
    """
    Exception to be thrown if an invalid password is submitted to be hashed.
    """

    pass


### Stolen from: https://github.com/BrettVerney/ciscoPWDhasher/
def cisco_password_check(password: str):
    """
    Checks cleartext password for invalid characters
    :param pwd: Clear text password
    :raises InvalidPassword: If the password contains invalid characters not supported by Cisco
    :return: None
    """
    invalid_chars = r"?\""
    if len(password) > 127:
        raise InvalidPassword(
            "Password must be between 1 and 127 characters in length."
        )
    if any(char in invalid_chars for char in password):
        raise InvalidPassword(r"? and \" are invalid characters for Cisco passwords.")


### Stolen from: https://github.com/BrettVerney/ciscoPWDhasher/
def cisco_type9(password: str, salt: Optional[str] = None) -> str:
    """
    Hashes password to Cisco type 9
    :param pwd: Clear text password
    :raises InvalidPassword: If the password contains invalid characters not supported by Cisco
    :return: Hashed password
    """
    if not salt:
        salt_chars = []
        for _ in range(14):
            salt_chars.append(random.choice(_CISCO_B64CHARS))
        salt = "".join(salt_chars)

    cisco_password_check(password)

    # Create the hash
    hash_str = scrypt.hash(password.encode(), salt.encode(), 16384, 1, 1, 32)
    # Convert the hash from Standard Base64 to Cisco Base64
    hash_str = base64.b64encode(hash_str).decode().translate(B64TABLE)[:-1]

    # Print the hash in the Cisco IOS CLI format
    password_string = f"$9${salt}${hash_str}"
    return password_string


def b62encode(data: bytes) -> str:
    """
    Encode a byte string and return the base62 encoded string.
    """
    num = int.from_bytes(data, sys.byteorder)
    if num == 0:
        return BASE62[0]
    arr = []
    arr_append = arr.append  # Extract bound-method for faster access.
    _divmod = divmod  # Access to locals is faster.
    base = len(BASE62)
    while num:
        num, rem = _divmod(num, base)
        arr_append(BASE62[rem])

    arr.reverse()
    return "".join(arr)


@lru_cache()
def generate_hash(
    hash_type: str, password: str, salt: Optional[str] = None
) -> Optional[str]:
    """
    Generates a hash from the plain-text password, and a salt.
    """
    hashed_password = None

    # MD5
    if hash_type == "1":
        if not salt:
            salt_bytes = os.urandom(3)
            salt = b62encode(salt_bytes)
        hashed_password = passlib.hash.md5_crypt.hash(password, salt=salt)
    # SHA512
    elif hash_type == "6":
        if not salt:
            salt_bytes = os.urandom(6)
            salt = b62encode(salt_bytes)
        hashed_password = passlib.hash.sha512_crypt.hash(
            password, rounds=5000, salt=salt
        )
    # Scrypt
    elif hash_type == "9":
        hashed_password = cisco_type9(password, salt=salt)

    return hashed_password


def parse_hash_components(
    hash_str: str,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Split a full login hash into it's components:
    1. Algorithm identifier
    2. (optional) Salt
    3. Hash
    """
    hash_list = hash_str.split("$")
    if len(hash_list) == 3:
        _, alg, hash_str = hash_list
        return alg, None, hash_str
    if len(hash_list) == 4:
        _, alg, salt, hash_str = hash_list
        return alg, salt, hash_str

    return None, None, None
