import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "core"))

import luauast                                    # noqa: E402  (core/luauast.py)
from obf import compiler as C                     # noqa: E402
from obf import emit as E                         # noqa: E402


def obfuscate(source, options):
    ast = luauast.parse(source)
    rng = random.Random(options.get("seed"))
    opmap = C.make_opmap(rng) if hasattr(C, "make_opmap") else None
    if opmap is None:
        from obf.emit import make_opmap
        opmap = make_opmap(rng)
    program = C.Program()
    # the four operands of an instruction are stored in a per build order, so
    # the bytecode layout is not a fixed pattern
    operand_order = [0, 1, 2, 3]
    rng.shuffle(operand_order)
    comp = C.Compiler(program, opmap, operand_order)
    comp.compile(ast)
    text = E.build_payload(program, {
        "rng": rng,
        "opmap": opmap,
        "operand_order": operand_order,
        "sled": options.get("sled"),
        "min_size": options.get("min_size"),
        "max_size": options.get("max_size"),
        "no_compress": options.get("no_compress"),
        "no_trap": options.get("no_trap"),
    })
    return text, program


def main(argv=None):
    ap = argparse.ArgumentParser(description="Luraph v15.1 style obfuscator")
    ap.add_argument("input", help="Luau source file")
    ap.add_argument("-o", "--output", help="output file")
    ap.add_argument("--seed", type=int, default=None, help="random seed (build reproducibility)")
    ap.add_argument("--no-compress", action="store_true", help="do not compress the program section")
    ap.add_argument("--no-trap", action="store_true", help="disable the anti tamper trap")
    ap.add_argument("--sled", type=int, default=100000000,
                    help="size of the virtual nop sled (0 disables it)")
    ap.add_argument("--min-size", type=int, default=100 * 1024,
                    help="minimum payload size in bytes (0 disables padding)")
    ap.add_argument("--max-size", type=int, default=5 * 1024 * 1024,
                    help="maximum payload size in bytes")
    ap.add_argument("--stats", action="store_true", help="print payload statistics")
    args = ap.parse_args(argv)

    with open(args.input, "rb") as f:
        raw = f.read()
    source = raw.decode("latin-1")

    options = {
        "seed": args.seed,
        "no_compress": args.no_compress,
        "no_trap": args.no_trap,
        "sled": args.sled,
        "min_size": args.min_size,
        "max_size": args.max_size,
    }
    text, program = obfuscate(source, options)

    out = args.output or (os.path.splitext(args.input)[0] + ".obf.lua")
    with open(out, "wb") as f:
        f.write(text.encode("utf-8"))

    if args.stats:
        total = sum(len(p.code) for p in program.protos)
        sled = sum(getattr(p, "sled", 0) for p in program.protos)
        print("protos   : %d" % len(program.protos))
        print("instrs   : %d" % (total // C.WIDTH))
        print("nop sled : %d" % sled)
        print("strings  : %d" % len(program.strings))
        print("input    : %d bytes" % len(raw))
        print("output   : %d bytes" % len(text))
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
