"""Serialization, encryption and compression for the Luraph style payload.

The program is flattened into one integer array, packed into a byte string,
encrypted with a modular keystream and (optionally) compressed with a
small LZ77 variant.  String constants live in a separate section so the VM
can decrypt them one by one (Luraph's `LPH_ENCSTR`).

The crypto is deliberately *bit free*: the vm has to rebuild the keystream
and the integrity hash with plain arithmetic, so the payload never needs a
`bit32.*` function (that alone was a fingerprint).
"""

import base64
import struct

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# --------------------------------------------------------------------------
# symbol alphabet
# --------------------------------------------------------------------------
# The payload is not plain base64 anymore: every 6 bit group is turned into a
# letter or a symbol, so a protected file reads like unicode soup instead of
# an ascii blob.  All symbols are unique code points and utf-8 is self
# synchronising, so the vm can walk the byte stream symbol by symbol and
# rebuild the 64 entry lookup table at startup.
#
# Every build mixes three kinds of symbols:
#   * lower case letters
#   * upper case letters
#   * greek letters (psi, lambda, mu, eta, alpha, beta, epsilon, gamma, delta,
#     zeta, eta, theta, iota, kappa)

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# 13 unique Greek letters for sufficient unique symbols (64 total alphabet)
# Using: ψ λ μ α β ε γ δ ζ η θ ι κ
CORE_SYMBOLS = "ψλμαβεγδζηθικ"

# Only Greek letters as symbols - no Latin1, no math symbols, no punctuation
SYMBOLS = CORE_SYMBOLS

SYMBOL_POOL = LOWER + UPPER + CORE_SYMBOLS

ALPHABET_SIZE = 64

# how many of each kind every build contains
GREEK_COUNT = len(CORE_SYMBOLS)
LOWER_COUNT = 13
UPPER_COUNT = 13


def symbol_pool():
    """Every candidate symbol, unique, in a stable order."""
    return list(dict.fromkeys(SYMBOL_POOL))


def make_alphabet(rng):
    """A per build alphabet of 64 symbols.

    Every build mixes lower case letters, upper case letters, and greek letters.
    No other symbols are used. The order is shuffled, so two builds never look the same.
    """
    lower = [c for c in LOWER]
    upper = [c for c in UPPER]
    rng.shuffle(lower)
    rng.shuffle(upper)
    # Start with all Greek letters, then add lower/upper, then fill from pool
    chosen = list(CORE_SYMBOLS)
    chosen += lower[:LOWER_COUNT]
    chosen += upper[:UPPER_COUNT]
    # Fill the rest from the full pool (which includes all Greek, lower, upper)
    rest = [c for c in symbol_pool() if c not in chosen]
    rng.shuffle(rest)
    chosen += rest[:ALPHABET_SIZE - len(chosen)]
    rng.shuffle(chosen)
    return "".join(chosen)



def b64_encode(data, alphabet):
    """base64 -> unicode symbols.

    The padding is dropped: the vm rebuilds the byte count from the bit
    stream, so the blob never contains an ascii '=' that would break the
    symbol walk.
    """
    enc = base64.b64encode(data).decode("ascii").rstrip("=")
    table = str.maketrans(STD, alphabet)
    return enc.translate(table)


# --------------------------------------------------------------------------
# keystream
# --------------------------------------------------------------------------
# A multiplicative congruential generator instead of xorshift32: the vm can
# compute it with plain arithmetic, so the payload needs no bit32 at all.

LCG_MUL = 48271
LCG_MOD = 2147483647


# every build uses a different linear congruential generator, so the
# keystream itself is not a fingerprint
LCG_SETS = (
    (48271, 2147483647, 65536),
    (16807, 2147483647, 65536),
    (69621, 2147483647, 32768),
    (48271, 2147483647, 32768),
)


def _lcg(x, variant=0):
    mul, mod, _mask = LCG_SETS[variant % len(LCG_SETS)]
    return (x * mul) % mod


def lcg_seed(seed, variant=0):
    _mul, mod, _mask = LCG_SETS[variant % len(LCG_SETS)]
    x = seed % mod
    return x if x else 1


def keystream(seed, length, variant=0):
    """Additive keystream (byte wise, mod 256)."""
    mul, mod, mask = LCG_SETS[variant % len(LCG_SETS)]
    out = bytearray(length)
    x = lcg_seed(seed, variant)
    for i in range(length):
        x = (x * mul) % mod
        y = x - (x % mask)
        out[i] = y % 256
    return bytes(out)


def add(data, key, mode=0):
    """modular combiner - the vm does exactly the same.

    mode 0: add, mode 1: subtract, mode 2: add with a scaled key
    """
    if not key:
        return data
    out = bytearray(len(data))
    kl = len(key)
    for i, b in enumerate(data):
        k = key[i % kl]
        if mode == 1:
            out[i] = (b - k) % 256
        elif mode == 2:
            out[i] = (b + k * 3) % 256
        else:
            out[i] = (b + k) % 256
    return bytes(out)


STRING_SEED_MULS = (2246822519, 2654435761, 3266489917, 668265263)


def string_seed(base, index, variant=0):
    mul = STRING_SEED_MULS[variant % len(STRING_SEED_MULS)]
    return (base + index * mul) & 0xFFFFFFFF


HASH_SETS = (
    (2166136261, 65599, 1),
    (2166136261, 1000003, 1),
    (3735928559, 1048573, 7),
)


def phash(data, variant=0):
    """32 bit hash - identical in python and in the vm."""
    h0, mul, scale = HASH_SETS[variant % len(HASH_SETS)]
    h = h0
    for b in data:
        h = (h * mul + b * scale) % 4294967296
    return h


def canaries(ints, count=16):
    """Pick (index, value) pairs spread over the program for the runtime
    integrity check."""
    n = len(ints)
    if n < 32 or count <= 0:
        return []
    out = []
    for i in range(count):
        idx = 8 + (n - 16) * i // max(1, count - 1)
        v = ints[idx] & 0xFFFFFFFF
        if v >= 0x80000000:
            v -= 0x100000000          # the vm compares signed words
        out.append((idx, v))
    return out


# --------------------------------------------------------------------------
# LZ77 (tiny window, byte oriented)
# --------------------------------------------------------------------------

def compress(data):
    """LZ77: 0x00 <count> <literal bytes> | 0x01 <len> <dist lo> <dist hi>."""
    out = bytearray()
    i = 0
    n = len(data)
    table = {}

    def match_at(pos, limit):
        """best (len, dist) of a match at pos, len < limit"""
        best_len = 0
        best_dist = 0
        if pos + 3 > n:
            return 0, 0
        key = data[pos:pos + 3]
        for cand in table.get(key, ())[-32:]:
            dist = pos - cand
            if dist <= 0 or dist > 65535:
                continue
            ln = 0
            while ln < limit and pos + ln < n and data[cand + ln] == data[pos + ln]:
                ln += 1
            if ln > best_len:
                best_len = ln
                best_dist = dist
                if ln >= limit:
                    break
        return best_len, best_dist

    while i < n:
        best_len, best_dist = match_at(i, 255)
        if best_len >= 4:
            out.append(1)
            out.append(best_len)
            out.append(best_dist & 0xFF)
            out.append((best_dist >> 8) & 0xFF)
            tok_start = i
            i += best_len
        else:
            start = i
            lit = bytearray()
            while i < n and len(lit) < 250:
                if match_at(i, 4)[0] >= 4:
                    break
                lit.append(data[i])
                i += 1
            if i == start:
                lit.append(data[i])
                i += 1
            out.append(0)
            out.append(len(lit))
            out.extend(lit)
            tok_start = start
        for j in range(tok_start, i):
            if j + 3 <= n:
                key = data[j:j + 3]
                lst = table.setdefault(key, [])
                lst.append(j)
                if len(lst) > 32:
                    del lst[:-32]
    return bytes(out)


# --------------------------------------------------------------------------
# program serialization
# --------------------------------------------------------------------------

def modinv(a, m=256):
    """Modular inverse of an odd number modulo 256."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 1


def encode_op(op, key, mode=0):
    if mode % 2 == 1:
        return (op * key) % 256
    return (op + key) % 256


def serialize(program, canary_count=16, opkey_mode=0):
    """-> (ints, string_section_bytes)"""
    ints = []
    ints.append(len(program.protos))
    ints.append(len(program.strings))
    for proto in program.protos:
        ints.append(proto.nparams)
        ints.append(proto.nregs)
        ints.append(proto.nlocals)
        ints.append(1 if proto.vararg else 0)
        ints.append(len(proto.upvals))
        ints.append(len(proto.code))
        if opkey_mode % 2 == 1:
            ints.append(modinv(proto.key & 0xFF) & 0xFF)
        else:
            ints.append(proto.key & 0xFF)
        ints.append(proto.sled & 0xFFFFFFFF)
        for i in range(0, len(proto.code), 5):
            ints.append(encode_op(proto.code[i], proto.key, opkey_mode))
            ints.extend(proto.code[i + 1:i + 5])
        for kind, idx in proto.upvals:
            ints.append(kind)
            ints.append(idx)
    str_offsets = []
    blob = bytearray()
    for s in program.strings:
        # the constants are raw byte strings (the source is read as latin-1),
        # so they must be stored byte for byte - no utf-8 expansion
        data = s.encode("latin-1", "replace")
        str_offsets.append((len(blob), len(data)))
        blob.extend(data)
    for off, ln in str_offsets:
        ints.append(off)
        ints.append(ln)
    cans = canaries(ints, canary_count)
    for idx, val in cans:
        ints.append(idx)
        ints.append(val)
    return ints, bytes(blob), str_offsets, len(cans)


def pack_ints(ints):
    out = bytearray()
    for v in ints:
        out.extend(struct.pack("<i", int(v)))
    return bytes(out)


WINDOW_COUNT = 16
WINDOW_SIZE = 64


def window_offsets(total, count=WINDOW_COUNT, size=WINDOW_SIZE):
    """Offsets of the integrity windows inside the program section."""
    if total <= size:
        return [0] * count
    if count <= 1:
        return [0]
    return [(i * (total - size)) // (count - 1) for i in range(count)]


def window_hashes(prog, count=WINDOW_COUNT, size=WINDOW_SIZE):
    offs = window_offsets(len(prog), count, size)
    return [(off, phash(prog[off:off + size])) for off in offs]


def build_blob(program, seed, compress_data=True, marker=b"\x00\x00\x00\x00",
               lib0=0, prb0=0, mtb0=0, windows=16, canary_count=16, variant=None,
               field_order=None):
    """-> (bytes, layout)

    The header is plaintext (it only holds lengths, hashes and the seed)
    but it starts with a *random* per build marker, so no fixed magic string
    can be searched for in a protected file.  The header *fields* are also
    written in a random order and the crypto variants change per build, so
    the payload cannot be recognised (or repacked) by a fixed pattern.
    """
    variant = variant or {}
    v_ks = int(variant.get("ks", 0))
    v_comb = int(variant.get("comb", 0))
    v_hash = int(variant.get("hash", 0))
    v_ss = int(variant.get("ss", 0))
    v_op = int(variant.get("op", 0))
    ints, strblob, _, ncans = serialize(program, canary_count, v_op)
    prog = pack_ints(ints)
    ph = phash(prog, v_hash)
    wins = [(off, phash(prog[off:off + WINDOW_SIZE], v_hash))
            for off in window_offsets(len(prog), count=windows, size=WINDOW_SIZE)]
    if compress_data:
        cprog = compress(prog)
        if len(cprog) < len(prog):
            prog = cprog
            cflag = 1
        else:
            cflag = 0
    else:
        cflag = 0
    # string section: each string encrypted with its own seed (no length
    # prefix; the lengths live in the int table as SLEN2).
    sec = bytearray()
    for i, s in enumerate(program.strings):
        data = s.encode("latin-1", "replace")
        enc = add(data, keystream(string_seed(seed, i, v_ss), len(data), v_ks), v_comb)
        sec.extend(enc)
    sec = bytes(sec)
    strh = phash(sec, v_hash) if sec else 0
    fields = [
        ("SEED", seed & 0xFFFFFFFF),
        ("PLEN", len(prog)),
        ("SLEN", len(sec)),
        ("CFL", cflag),
        ("PHASH", (ph + seed) & 0xFFFFFFFF),
        ("NCAN", ncans),
        ("NWIN", len(wins)),
        ("STRH", strh & 0xFFFFFFFF),
        ("LIB0", lib0),
        ("PRB0", prb0),
        ("MTB0", mtb0),
    ]
    if field_order:
        fields = [fields[i] for i in field_order]
    head = marker[:4].ljust(4, b"\x00")
    layout = []
    off = 4
    for name, val in fields:
        head += struct.pack("<I", val & 0xFFFFFFFF)
        layout.append((name, off))
        off += 4
    for _, h in wins:
        head += struct.pack("<I", h & 0xFFFFFFFF)
    meta = {"layout": layout, "win_base": off,
            "prog_base": off + 4 * len(wins)}
    body = head + add(prog, keystream(seed, len(prog), v_ks), v_comb) + sec
    # a trailer hash over everything that came before it
    return body + struct.pack("<I", phash(body, v_hash)), meta
