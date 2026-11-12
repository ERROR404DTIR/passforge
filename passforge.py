#!/usr/bin/env python3
"""passforge - secure password / passphrase / PIN generator with an entropy meter.

One file, zero dependencies, offline. Just run it:  python passforge.py
"""
import argparse
import getpass
import math
import secrets
import string
import sys

__version__ = "1.0.0"

LOWER, UPPER, DIGITS = string.ascii_lowercase, string.ascii_uppercase, string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"
AMBIGUOUS = set("O0oIl1|`'\"")

WORDS = list(dict.fromkeys("""
able acid acorn actor adapt alarm album alert alien alpha amber anchor angle apple april arrow atlas attic
autumn avid award bacon badge baker banjo barn basil beach beam bench berry bike birch bison blade blank
blaze bloom boat bold bolt bonus book boost brave bread brick bridge brook brush cabin cable cactus camel
candy canoe cargo carpet castle cedar chalk charm cheese cherry chess chime cider circle civic clay cliff
clock cloud clover coast cobra cocoa comet coral cotton crane crisp crown cubic daisy dance delta denim
desert dial diner disco dock dolphin dragon dream drift drum eagle earth echo elbow elder ember engine epic
fable falcon fancy farm feast fern ferry fiber field finch flame flint flute focus forest fossil fox frost
fruit galaxy garden gecko ginger glacier globe grain grape gravel grove guitar habit harbor hazel heart
hedge herb honey horizon hound humble igloo indigo iron island ivory jacket jade jelly jewel jungle kayak
kettle kiwi koala ladder lagoon lantern laser lemon lilac linen lion lotus lunar magnet mango maple marble
meadow melon mint mirror moose mosaic motor mountain nectar noble north nutmeg oasis ocean olive onyx opal
orbit otter oxygen paddle panda paper parrot pearl pepper piano pilot pine planet plum polar pond poppy
prairie pulse puzzle quartz quill rabbit radar rain raven reef ribbon river robin rocket saddle saffron
sage sail salmon sand scarlet seed shadow silver sketch slate solar spark spice spruce stone storm sugar
summit sunset swan table tango thistle thunder tiger timber topaz tulip tundra turtle umber valley velvet
violet walnut wave willow winter wolf yacht zebra zenith
""".split()))

COMMON = ("password", "passw0rd", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou",
          "abc123", "111111", "dragon", "monkey", "football", "login", "master", "secret")
SEQUENCES = ("abcdefgh", "12345678", "qwertyui", "asdfghjk", "zxcvbnm")


def rate(bits):
    for limit, label in ((28, "very weak"), (36, "weak"), (60, "fair"), (80, "strong")):
        if bits < limit:
            return label
    return "very strong"


def make_password(length, groups):
    pool = "".join(groups)
    while True:  # rejection sampling keeps the distribution uniform
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(ch in g for ch in pw) for g in groups):
            return pw, length * math.log2(len(pool))


def make_passphrase(count, sep, capitalize):
    words = [secrets.choice(WORDS) for _ in range(count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return sep.join(words), count * math.log2(len(WORDS))


def check(pw):
    pool = 0
    pool += 26 if any(c in LOWER for c in pw) else 0
    pool += 26 if any(c in UPPER for c in pw) else 0
    pool += 10 if any(c in DIGITS for c in pw) else 0
    pool += 33 if any(c not in LOWER + UPPER + DIGITS for c in pw) else 0
    bits = len(pw) * math.log2(pool) if pool else 0.0
    notes = []
    low = pw.lower()
    if any(w in low for w in COMMON):
        notes.append("contains a very common password")
        bits = min(bits, 20.0)
    if any(s in low for s in SEQUENCES):
        notes.append("contains a keyboard/number sequence")
        bits *= 0.6
    if pw and len(set(pw)) <= len(pw) / 2:
        notes.append("many repeated characters")
        bits *= 0.7
    if len(pw) < 12:
        notes.append("shorter than 12 characters")
    return bits, notes


def main(argv=None):
    p = argparse.ArgumentParser(prog="passforge", description="Secure password / passphrase / PIN generator.")
    p.add_argument("-l", "--length", type=int, default=20, help="password length (default 20)")
    p.add_argument("-n", "--count", type=int, default=1, help="how many to generate (default 1)")
    p.add_argument("--no-upper", action="store_true", help="no uppercase letters")
    p.add_argument("--no-digits", action="store_true", help="no digits")
    p.add_argument("--no-symbols", action="store_true", help="no symbols")
    p.add_argument("--no-ambiguous", action="store_true", help="skip look-alike characters (O 0 l 1 I ...)")
    p.add_argument("-w", "--words", type=int, metavar="N", help="generate an N-word passphrase instead")
    p.add_argument("-s", "--sep", default="-", help="passphrase separator (default '-')")
    p.add_argument("--capitalize", action="store_true", help="capitalize passphrase words")
    p.add_argument("--pin", type=int, metavar="N", help="generate a numeric PIN with N digits")
    p.add_argument("--check", nargs="?", const="", metavar="PASSWORD",
                   help="rate a password (leave empty to type it hidden)")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the result, no entropy line")
    p.add_argument("-V", "--version", action="version", version="passforge " + __version__)
    a = p.parse_args(argv)

    if a.check is not None:
        pw = a.check or getpass.getpass("Password to check: ")
        bits, notes = check(pw)
        print("entropy ~%.0f bits - %s" % (bits, rate(bits)))
        for n in notes:
            print(" - " + n)
        return 0

    if a.count < 1 or a.count > 1000:
        p.error("--count must be between 1 and 1000")

    if a.pin is not None:
        if not 1 <= a.pin <= 64:
            p.error("--pin must be between 1 and 64")
        make = lambda: ("".join(secrets.choice(DIGITS) for _ in range(a.pin)), a.pin * math.log2(10))
    elif a.words is not None:
        if not 1 <= a.words <= 32:
            p.error("--words must be between 1 and 32")
        make = lambda: make_passphrase(a.words, a.sep, a.capitalize)
    else:
        groups = [LOWER] + ([UPPER] if not a.no_upper else []) + ([DIGITS] if not a.no_digits else []) \
            + ([SYMBOLS] if not a.no_symbols else [])
        if a.no_ambiguous:
            groups = ["".join(c for c in g if c not in AMBIGUOUS) for g in groups]
        if not 1 <= a.length <= 1024:
            p.error("--length must be between 1 and 1024")
        if a.length < len(groups):
            p.error("--length is too short for the selected character groups")
        make = lambda: make_password(a.length, groups)

    bits = 0.0
    for _ in range(a.count):
        text, bits = make()
        print(text)
    if not a.quiet:
        print("entropy ~%.0f bits - %s" % (bits, rate(bits)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
