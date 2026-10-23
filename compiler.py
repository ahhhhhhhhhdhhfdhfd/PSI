"""Luraph v15.1 style obfuscator - virtual machine compiler.

Compiles a Luau AST (as produced by `core/luauast.py`) into a register based
bytecode program that the emitted VM (see `emit.py`) interprets.

The instruction set mirrors the ideas the Luraph v15 devirtualizer reverses:

* every operation is a flat opcode in one big array -> the original control
  flow is flattened into a state machine (no `if`/`while` left in the payload),
* locals live in "cells" when they are captured, so closures share them by
  reference (Lua semantics),
* string / number constants are not stored inside the program; they live in
  an encrypted string table that is decrypted lazily, one entry at a time
  (Luraph's `LPH_ENCSTR`),
* the whole program is encrypted and (optionally) compressed before it is
  embedded into the payload.

Opcode numbers are assigned per build, so two builds never share the same
dispatch tree.
"""

# --------------------------------------------------------------------------
# opcodes
# --------------------------------------------------------------------------

OP_MOVE = "MOVE"            # a b        R[a] = R[b]
OP_CONST = "CONST"          # a b        R[a] = lazy constant #b
OP_NUM = "NUM"              # a b        R[a] = b
OP_NIL = "NIL"              # a          R[a] = nil
OP_TRUE = "TRUE"            # a          R[a] = true
OP_FALSE = "FALSE"          # a          R[a] = false
OP_GETGLOBAL = "GETGLOBAL"  # a b        R[a] = ENV[string #b]
OP_SETGLOBAL = "SETGLOBAL"  # a b        ENV[string #b] = R[a]
OP_GETTABLE = "GETTABLE"    # a b c      R[a] = R[b][R[c]]
OP_SETTABLE = "SETTABLE"    # a b c      R[a][R[b]] = R[c]
OP_GETFIELD = "GETFIELD"    # a b c      R[a] = R[b][string #c]
OP_SETFIELD = "SETFIELD"    # a b c      R[a][string #c] = R[b]
OP_SETTABLEK = "SETTABLEK"  # a b c      R[a][string #c] = R[b]
OP_NEWTABLE = "NEWTABLE"    # a b        R[a] = {}
OP_SETLIST = "SETLIST"      # a b c      R[a][b] = R[c]
OP_ADD = "ADD"
OP_SUB = "SUB"
OP_MUL = "MUL"
OP_DIV = "DIV"
OP_IDIV = "IDIV"
OP_MOD = "MOD"
OP_POW = "POW"
OP_CONCAT = "CONCAT"
OP_LT = "LT"
OP_LE = "LE"
OP_GT = "GT"
OP_GE = "GE"
OP_EQ = "EQ"
OP_NE = "NE"
OP_NOT = "NOT"              # a b        R[a] = not R[b]
OP_NEG = "NEG"              # a b        R[a] = -R[b]
OP_LEN = "LEN"              # a b        R[a] = #R[b]
OP_JMP = "JMP"              # a          pc += a
OP_JMPF = "JMPF"            # a b        if not R[a] then pc += b
OP_JMPT = "JMPT"            # a b        if R[a] then pc += b
OP_CALL = "CALL"            # a b c      R[a..] = R[a](R[a+1..a+b-1])
OP_CALLV = "CALLV"          # a b c d    call R[a] with b args, results -> R[c..], count -> R[d]
OP_CALLX = "CALLX"          # a b c d    call R[a] with b fixed args + the R[c..] args (count R[d])
OP_FORCALL = "FORCALL"      # a          k,v = R[a](R[a+1],R[a+2]) -> R[a+3],R[a+4]
OP_ENTERLVL = "ENTERLVL"  # a          enter the nested vm level (proto a)
OP_RET = "RET"              # a b        return R[a..a+b-1]
OP_CLOSURE = "CLOSURE"      # a b        R[a] = closure(proto #b)
OP_GETUPVAL = "GETUPVAL"    # a b        R[a] = U[b][1]
OP_SETUPVAL = "SETUPVAL"    # a b        U[b][1] = R[a]
OP_NEWCELL = "NEWCELL"      # a          R[a] = {nil}
OP_GETCELL = "GETCELL"      # a b        R[a] = R[b][1]
OP_SETCELL = "SETCELL"      # a b        R[a][1] = R[b]
OP_VARARG1 = "VARARG1"      # a          R[a] = first vararg
OP_VARARGTABLE = "VARARGTABLE"   # a    R[a] = { every vararg }
OP_FORCOND = "FORCOND"      # a b c d    R[a] = for-condition(i=b, to=c, step=d)
OP_SELF = "SELF"            # a b c      R[a] = R[b][string #c]; R[a+1] = R[b]
OP_JUNK = "JUNK"            # a          no-op filler

BINARY_OPS = {
    "Add": OP_ADD, "Sub": OP_SUB, "Mul": OP_MUL, "Div": OP_DIV,
    "FloorDiv": OP_IDIV, "Mod": OP_MOD, "Pow": OP_POW, "Concat": OP_CONCAT,
    "CompareLt": OP_LT, "CompareLe": OP_LE, "CompareGt": OP_GT,
    "CompareGe": OP_GE, "CompareEq": OP_EQ, "CompareNe": OP_NE,
}

UNARY_OPS = {"Not": OP_NOT, "Minus": OP_NEG, "Len": OP_LEN}

ALL_OPS = [
    OP_MOVE, OP_CONST, OP_NUM, OP_NIL, OP_TRUE, OP_FALSE,
    OP_GETGLOBAL, OP_SETGLOBAL, OP_GETTABLE, OP_SETTABLE, OP_GETFIELD,
    OP_SETFIELD, OP_SETTABLEK, OP_NEWTABLE, OP_SETLIST,
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_IDIV, OP_MOD, OP_POW, OP_CONCAT,
    OP_LT, OP_LE, OP_GT, OP_GE, OP_EQ, OP_NE,
    OP_NOT, OP_NEG, OP_LEN,
    OP_JMP, OP_JMPF, OP_JMPT, OP_CALL, OP_RET,
    OP_CLOSURE, OP_GETUPVAL, OP_SETUPVAL, OP_NEWCELL, OP_GETCELL, OP_SETCELL,
    OP_VARARG1, OP_VARARGTABLE, OP_FORCOND, OP_SELF, OP_JUNK,
    OP_CALLV, OP_CALLX, OP_FORCALL, OP_ENTERLVL,
]

WIDTH = 5                   # op, a, b, c, d


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

class Proto(object):
    def __init__(self, index):
        self.index = index
        self.code = []
        self.nparams = 0
        self.nregs = 0
        self.nlocals = 0
        self.vararg = False
        self.upvals = []      # (kind, index): 0 = parent local, 1 = parent upval
        self.key = 0          # per level opcode key (dynamic opcodes)
        self.loader = False   # true for the outer loader level
        self.sled = 0         # size of the virtual nop sled of this proto


class Program(object):
    def __init__(self):
        self.protos = []
        self.strings = []
        self.string_index = {}

    def add_string(self, text):
        """Plain string constant (type prefix 0). Returns a 1-based index."""
        key = "\0" + text
        if key in self.string_index:
            return self.string_index[key] + 1
        idx = len(self.strings)
        self.strings.append(key)
        self.string_index[key] = idx
        return idx + 1

    def add_number(self, value):
        """Numeric constant, stored as text so it can be encrypted lazily."""
        text = "\1" + repr(float(value))
        if text in self.string_index:
            return self.string_index[text] + 1
        idx = len(self.strings)
        self.strings.append(text)
        self.string_index[text] = idx
        return idx + 1

    def new_proto(self):
        p = Proto(len(self.protos))
        self.protos.append(p)
        return p


# --------------------------------------------------------------------------
# compiler
# --------------------------------------------------------------------------

class FuncInfo(object):
    def __init__(self, node, parent, index):
        self.node = node
        self.parent = parent
        self.index = index
        self.children = []
        self.declared = []
        self.reg = {}
        self.boxed = set()
        self.free = set()
        self.upvals = []
        self.upval_index = {}
        self.nlocals = 0
        self.nloopregs = 0
        self.tmp_base = 0


class Compiler(object):
    def __init__(self, program, opmap, operand_order=(0, 1, 2, 3)):
        self.p = program
        self.opmap = opmap
        # the four operands of an instruction are stored in a per build
        # order, so the bytecode layout is not a fixed pattern
        self.operand_order = list(operand_order)
        self.owner = {}
        self.localinfo = {}
        self.nodefunc = {}
        self.funcs = []
        self.tmp = 0
        self.tmp_max = 0
        self.breaks = []
        self.continues = []
        self.forin_fresh = {}
        self.cur = None
        self.cur_func = None
        self.loop_used = 0

    # -- utilities -------------------------------------------------------

    @staticmethod
    def key_of(localnode):
        loc = localnode.get("location")
        if loc:
            return loc
        return "@" + str(localnode.get("name", "?"))

    # -- analysis --------------------------------------------------------

    def body_assigns(self, node, key):
        """True when `node` assigns to the local identified by `key`."""
        if isinstance(node, dict):
            t = node.get("type")
            if t in ("AstStatFunction", "AstStatLocalFunction", "AstExprFunction"):
                return False
            if t == "AstStatAssign":
                for v in node.get("vars", []):
                    if v.get("type") == "AstExprLocal" and self.key_of(v["local"]) == key:
                        return True
            for k, v in node.items():
                if k in ("location", "luauType"):
                    continue
                if self.body_assigns(v, key):
                    return True
        elif isinstance(node, list):
            for v in node:
                if self.body_assigns(v, key):
                    return True
        return False

    def analyze_function(self, fnode, parent):
        fi = FuncInfo(fnode, parent, len(self.funcs))
        self.funcs.append(fi)
        self.nodefunc[id(fnode)] = fi
        if parent is not None:
            parent.children.append(fi)
        refs = set()
        declared = []
        always_boxed = set()

        def declare(node):
            k = self.key_of(node)
            declared.append(k)
            self.owner[k] = fi

        if fnode.get("self"):
            declare(fnode["self"])
        for a in fnode.get("args", []):
            declare(a)

        def walk_expr(e):
            if not isinstance(e, dict):
                return
            t = e.get("type")
            if t == "AstExprLocal":
                refs.add(self.key_of(e["local"]))
            elif t == "AstExprFunction":
                child = self.analyze_function(e, fi)
                refs.update(child.refs)
            elif t in ("AstExprIndexName",):
                walk_expr(e.get("expr"))
            elif t in ("AstExprIndexExpr",):
                walk_expr(e.get("expr"))
                walk_expr(e.get("index"))
            elif t in ("AstExprCall",):
                walk_expr(e.get("func"))
                for a in e.get("args", []):
                    walk_expr(a)
            elif t in ("AstExprTable",):
                for it in e.get("items", []):
                    walk_expr(it.get("key"))
                    walk_expr(it.get("value"))
            elif t in ("AstExprBinary",):
                walk_expr(e.get("left"))
                walk_expr(e.get("right"))
            elif t in ("AstExprUnary",):
                walk_expr(e.get("expr"))
            elif t in ("AstExprGroup",):
                walk_expr(e.get("expr"))
            elif t in ("AstExprIfElse",):
                walk_expr(e.get("condition"))
                walk_expr(e.get("trueExpr"))
                walk_expr(e.get("falseExpr"))

        def walk_stat(s):
            if not isinstance(s, dict):
                return
            t = s.get("type")
            if t == "AstStatBlock":
                for st in s.get("body", []):
                    walk_stat(st)
            elif t == "AstStatLocal":
                for v in s.get("values", []):
                    walk_expr(v)
                for v in s.get("vars", []):
                    declare(v)
            elif t == "AstStatLocalFunction":
                declare(s["name"])
                walk_expr(s["func"])
            elif t == "AstStatFunction":
                walk_expr(s["func"])
            elif t == "AstStatAssign":
                for v in s.get("vars", []):
                    walk_expr(v)
                for v in s.get("values", []):
                    walk_expr(v)
            elif t == "AstStatExpr":
                walk_expr(s.get("expr"))
            elif t == "AstStatReturn":
                for v in s.get("list", []):
                    walk_expr(v)
            elif t == "AstStatIf":
                walk_expr(s.get("condition"))
                walk_stat(s.get("thenbody"))
                walk_stat(s.get("elsebody"))
            elif t == "AstStatWhile":
                walk_expr(s.get("condition"))
                walk_stat(s.get("body"))
            elif t == "AstStatRepeat":
                walk_stat(s.get("body"))
                walk_expr(s.get("condition"))
            elif t == "AstStatFor":
                walk_expr(s.get("from"))
                walk_expr(s.get("to"))
                walk_expr(s.get("step"))
                declare(s["var"])
                if self.body_assigns(s.get("body"), self.key_of(s["var"])):
                    always_boxed.add(self.key_of(s["var"]))
                walk_stat(s.get("body"))
            elif t == "AstStatForIn":
                for v in s.get("values", []):
                    walk_expr(v)
                for v in s.get("vars", []):
                    declare(v)
                    always_boxed.add(self.key_of(v))
                    if self.body_assigns(s.get("body"), self.key_of(v)):
                        self.forin_fresh[self.key_of(v)] = True
                walk_stat(s.get("body"))
            elif t == "AstStatDo":
                walk_stat(s.get("body"))
            elif t == "AstStatCompoundAssign":
                walk_expr(s.get("var"))
                walk_expr(s.get("value"))

        walk_stat(fnode.get("body"))
        fi.declared = declared
        fi.refs = refs
        fi.free = set(refs) - set(declared)
        fi.always_boxed = always_boxed
        return fi

    def count_loop_regs(self, block):
        total = 0

        def walk(s):
            nonlocal total
            if not isinstance(s, dict):
                return
            t = s.get("type")
            if t == "AstStatBlock":
                for st in s.get("body", []):
                    walk(st)
            elif t == "AstStatFor":
                total += 1
                walk(s.get("body"))
            elif t == "AstStatForIn":
                total += 9
                walk(s.get("body"))
            elif t == "AstStatIf":
                walk(s.get("thenbody"))
                walk(s.get("elsebody"))
            elif t == "AstStatWhile":
                walk(s.get("body"))
            elif t == "AstStatRepeat":
                walk(s.get("body"))
            elif t == "AstStatDo":
                walk(s.get("body"))

        walk(block)
        return total

    def resolve(self, fi):
        """Assign registers and resolve the upvalue chains (top down)."""
        reg = 0
        for k in fi.declared:
            fi.reg[k] = reg
            reg += 1
        fi.nlocals = reg
        fi.nloopregs = self.count_loop_regs(fi.node.get("body"))
        fi.tmp_base = fi.nlocals + fi.nloopregs
        if fi.parent is not None:
            for k in sorted(fi.free):
                owner = self.owner.get(k)
                if owner is fi.parent:
                    fi.upvals.append((0, owner.reg[k]))
                    fi.upval_index[k] = len(fi.upvals)  # 1-based
                    owner.boxed.add(k)
                elif k in fi.parent.upval_index:
                    fi.upvals.append((1, fi.parent.upval_index[k]))
                    fi.upval_index[k] = len(fi.upvals)  # 1-based
        fi.boxed |= fi.always_boxed

    def build_localinfo(self, fi):
        for k, r in fi.reg.items():
            self.localinfo[k] = {"reg": r, "boxed": k in fi.boxed, "func": fi}

    # -- code generation -------------------------------------------------

    def emit(self, op, a=0, b=0, c=0, d=0):
        code = self.cur.code
        code.append(self.opmap[op])
        vals = (int(a), int(b), int(c), int(d))
        order = self.operand_order
        code.append(vals[order[0]])
        code.append(vals[order[1]])
        code.append(vals[order[2]])
        code.append(vals[order[3]])

    def alloc_tmp(self, n=1):
        r = self.tmp
        self.tmp += n
        if self.tmp > self.tmp_max:
            self.tmp_max = self.tmp
        return r

    def alloc_loop(self, n):
        fi = self.cur_func
        base = fi.tmp_base - fi.nloopregs + self.loop_used
        self.loop_used += n
        return base

    def here(self):
        return len(self.cur.code)

    def patch(self, at, target, operand=1):
        # the operand slots are permuted per build, so the jump offset has to
        # be written to the slot that actually holds it
        slot = self.operand_order.index(operand - 1) + 1
        self.cur.code[at + slot] = target - (at + WIDTH)

    def compile(self, root_ast):
        root = self.analyze_function({"args": [], "body": root_ast, "vararg": False}, None)
        for _ in self.funcs:
            self.p.new_proto()
        self._resolve_all(root)
        self._localinfo_all(root)
        self._gen_all(root)
        self._add_loader_level()
        return self.p

    def _add_loader_level(self):
        """Wrap the program in an outer VM level.

        The loader proto only contains one instruction (`enter level`), it uses
        a different opcode key than the inner program - so the two levels have
        independent, dynamic dispatch tables.
        """
        loader = self.p.new_proto()
        loader.code = [self.opmap[OP_ENTERLVL], 0, 0, 0, 0]
        loader.nparams = 0
        loader.nregs = 4
        loader.nlocals = 0
        loader.vararg = False
        loader.upvals = []
        loader.loader = True

    def _resolve_all(self, fi):
        self.resolve(fi)
        for c in fi.children:
            self._resolve_all(c)

    def _localinfo_all(self, fi):
        self.build_localinfo(fi)
        for c in fi.children:
            self._localinfo_all(c)

    def _gen_all(self, fi):
        proto = self.p.protos[fi.index]
        self.cur = proto
        self.cur_func = fi
        self.tmp = fi.tmp_base
        self.tmp_max = fi.tmp_base
        self.loop_used = 0
        self.gen_block(fi.node.get("body"))
        self.emit(OP_RET, 0, 0)
        proto.code = self.cur.code
        proto.nparams = len(fi.node.get("args", [])) + (1 if fi.node.get("self") else 0)
        proto.nlocals = fi.nlocals
        proto.vararg = bool(fi.node.get("vararg"))
        proto.upvals = fi.upvals
        proto.nregs = self.tmp_max + 4
        for c in fi.children:
            self._gen_all(c)

    # -- statements ------------------------------------------------------

    def gen_block(self, block):
        if not isinstance(block, dict):
            return
        for st in block.get("body", []):
            self.gen_stat(st)

    def gen_stat(self, s):
        t = s.get("type")
        if t == "AstStatBlock":
            self.gen_block(s)
        elif t == "AstStatLocal":
            self.gen_local(s)
        elif t == "AstStatLocalFunction":
            self.gen_local_function(s)
        elif t == "AstStatFunction":
            self.gen_global_function(s)
        elif t == "AstStatAssign":
            self.gen_assign(s)
        elif t == "AstStatExpr":
            self.gen_expr(s.get("expr"))
        elif t == "AstStatReturn":
            self.gen_return(s)
        elif t == "AstStatIf":
            self.gen_if(s)
        elif t == "AstStatWhile":
            self.gen_while(s)
        elif t == "AstStatRepeat":
            self.gen_repeat(s)
        elif t == "AstStatFor":
            self.gen_for(s)
        elif t == "AstStatForIn":
            self.gen_forin(s)
        elif t == "AstStatDo":
            self.gen_block(s.get("body"))
        elif t == "AstStatBreak":
            self.emit(OP_JMP, 0)
            self.breaks.append(self.here() - WIDTH)
        elif t == "AstStatContinue":
            self.emit(OP_JMP, 0)
            self.continues.append(self.here() - WIDTH)
        elif t == "AstStatCompoundAssign":
            self.gen_compound(s)
        else:
            raise NotImplementedError("statement %s" % t)

    def gen_values(self, values, want):
        """Compile a value list; a trailing call expands to several results."""
        regs = []
        for i, v in enumerate(values):
            last = (i == len(values) - 1)
            if self.is_call(v):
                n = (want - i) if last else 1
                if n < 1:
                    n = 1
                base = self.gen_call(v, n)
                for k in range(n):
                    regs.append(base + k)
            else:
                regs.append(self.gen_expr(v))
        return regs

    def gen_local(self, s):
        vals = s.get("values", [])
        regs = self.gen_values(vals, len(s["vars"]))
        for i, var in enumerate(s["vars"]):
            info = self.localinfo[self.key_of(var)]
            r = info["reg"]
            src = regs[i] if i < len(regs) else None
            if info["boxed"]:
                self.emit(OP_NEWCELL, r)
                if src is not None:
                    self.emit(OP_SETCELL, r, src)
            elif src is not None:
                self.emit(OP_MOVE, r, src)
            else:
                self.emit(OP_NIL, r)

    def gen_local_function(self, s):
        info = self.localinfo[self.key_of(s["name"])]
        r = info["reg"]
        child = self.nodefunc[id(s["func"])]
        if info["boxed"]:
            self.emit(OP_NEWCELL, r)
            t = self.alloc_tmp()
            self.emit(OP_CLOSURE, t, child.index)
            self.emit(OP_SETCELL, r, t)
        else:
            self.emit(OP_CLOSURE, r, child.index)

    def gen_global_function(self, s):
        child = self.nodefunc[id(s["func"])]
        t = self.alloc_tmp()
        self.emit(OP_CLOSURE, t, child.index)
        name = s["name"]
        if name.get("type") == "AstExprGlobal":
            self.emit(OP_SETGLOBAL, t, self.p.add_string(name["global"]))
        elif name.get("type") == "AstExprIndexName":
            base = self.gen_expr(name["expr"])
            self.emit(OP_SETFIELD, base, t, self.p.add_string(name["index"]))

    def gen_assign(self, s):
        values = s.get("values", [])
        targets = s.get("vars", [])
        regs = self.gen_values(values, len(targets))
        for i, target in enumerate(targets):
            src = regs[i] if i < len(regs) else None
            if src is None:
                src = self.alloc_tmp()
                self.emit(OP_NIL, src)
            self.gen_store(target, src)

    @staticmethod
    def is_call(node):
        while isinstance(node, dict) and node.get("type") == "AstExprGroup":
            node = node.get("expr")
        return isinstance(node, dict) and node.get("type") == "AstExprCall"

    def gen_store(self, target, src):
        t = target.get("type")
        if t == "AstExprLocal":
            key = self.key_of(target["local"])
            info = self.localinfo[key]
            if info["func"] is not self.cur_func:
                idx = self.cur_func.upval_index.get(key, 0)
                self.emit(OP_SETUPVAL, src, idx)
            elif info["boxed"]:
                self.emit(OP_SETCELL, info["reg"], src)
            else:
                self.emit(OP_MOVE, info["reg"], src)
        elif t == "AstExprGlobal":
            self.emit(OP_SETGLOBAL, src, self.p.add_string(target["global"]))
        elif t == "AstExprIndexName":
            base = self.gen_expr(target["expr"])
            self.emit(OP_SETFIELD, base, src, self.p.add_string(target["index"]))
        elif t == "AstExprIndexExpr":
            base = self.gen_expr(target["expr"])
            key = self.gen_expr(target["index"])
            self.emit(OP_SETTABLE, base, key, src)
        else:
            raise NotImplementedError("assignment target %s" % t)

    def gen_return(self, s):
        lst = s.get("list", [])
        if not lst:
            self.emit(OP_RET, 0, 0)
            return
        regs = []
        for i, v in enumerate(lst):
            last = (i == len(lst) - 1)
            if self.is_call(v):
                base = self.gen_call(v, -1 if last else 1)
                if last:
                    self.emit(OP_RET, base, -1)
                    return
                regs.append(base)
            else:
                regs.append(self.gen_expr(v))
        base = self.alloc_tmp(len(regs))
        for i, r in enumerate(regs):
            if r != base + i:
                self.emit(OP_MOVE, base + i, r)
        self.emit(OP_RET, base, len(regs))

    def gen_if(self, s):
        cond = self.gen_expr(s["condition"])
        jf = self.here()
        self.emit(OP_JMPF, cond, 0)
        self.gen_block(s.get("thenbody"))
        jend = self.here()
        self.emit(OP_JMP, 0)
        self.patch(jf, self.here(), 2)
        self.gen_block(s.get("elsebody"))
        self.patch(jend, self.here())

    def gen_while(self, s):
        top = self.here()
        cond = self.gen_expr(s["condition"])
        jf = self.here()
        self.emit(OP_JMPF, cond, 0)
        bstart, cstart = len(self.breaks), len(self.continues)
        self.breaks.append(None)
        self.gen_block(s.get("body"))
        self.emit(OP_JMP, top - (self.here() + WIDTH))
        end = self.here()
        self.patch(jf, end, 2)
        for b in self.breaks[bstart:]:
            if b is not None:
                self.patch(b, end)
        del self.breaks[bstart:]
        for c in self.continues[cstart:]:
            if c is not None:
                self.patch(c, top)
        del self.continues[cstart:]

    def gen_repeat(self, s):
        top = self.here()
        bstart, cstart = len(self.breaks), len(self.continues)
        self.breaks.append(None)
        self.gen_block(s.get("body"))
        cond = self.gen_expr(s["condition"])
        jt = self.here()
        self.emit(OP_JMPT, cond, 0)
        self.emit(OP_JMP, top - (self.here() + WIDTH))
        end = self.here()
        self.patch(jt, end, 2)
        for b in self.breaks[bstart:]:
            if b is not None:
                self.patch(b, end)
        del self.breaks[bstart:]
        for c in self.continues[cstart:]:
            if c is not None:
                self.patch(c, top)
        del self.continues[cstart:]

    def gen_for(self, s):
        counter = self.alloc_loop(1)
        fromr = self.gen_expr(s["from"])
        tor = self.gen_expr(s["to"])
        step = s.get("step")
        if step is None:
            sr = self.alloc_tmp()
            self.emit(OP_NUM, sr, 1)
        else:
            sr = self.gen_expr(step)
        self.emit(OP_MOVE, counter, fromr)
        top = self.here()
        cref = self.alloc_tmp()
        self.emit(OP_MOVE, cref, counter)
        condr = self.alloc_tmp()
        self.emit(OP_FORCOND, condr, cref, tor, sr)
        jf = self.here()
        self.emit(OP_JMPF, condr, 0)
        info = self.localinfo[self.key_of(s["var"])]
        bodyreg = info["reg"]
        boxed = info["boxed"]
        if boxed:
            self.emit(OP_NEWCELL, bodyreg)
        tv = self.alloc_tmp()
        self.emit(OP_MOVE, tv, counter)
        if boxed:
            self.emit(OP_SETCELL, bodyreg, tv)
        else:
            self.emit(OP_MOVE, bodyreg, tv)
        self.breaks.append(None)
        bstart, cstart = len(self.breaks), len(self.continues)
        self.gen_block(s.get("body"))
        self.emit(OP_MOVE, tv, counter)
        self.emit(OP_ADD, tv, tv, sr)
        self.emit(OP_MOVE, counter, tv)
        self.emit(OP_JMP, top - (self.here() + WIDTH))
        end = self.here()
        self.patch(jf, end, 2)
        for b in self.breaks[bstart:]:
            if b is not None:
                self.patch(b, end)
        del self.breaks[bstart:]
        for c in self.continues[cstart:]:
            if c is not None:
                self.patch(c, top)
        del self.continues[cstart:]

    def gen_forin(self, s):
        state = self.alloc_loop(9)
        v0 = s["values"][0]
        if self.is_call(v0):
            # the for-in expression expands to (iterator, state, control)
            base = self.gen_call(v0, 3)
            for k in range(3):
                if base + k != state + k:
                    self.emit(OP_MOVE, state + k, base + k)
        else:
            v = self.gen_expr(v0)
            self.emit(OP_MOVE, state + 0, v)
            self.emit(OP_NIL, state + 1)
            self.emit(OP_NIL, state + 2)
        # keep the iterator so the loop can call it again
        self.emit(OP_MOVE, state + 3, state + 0)
        self.emit(OP_MOVE, state + 4, state + 1)
        self.emit(OP_MOVE, state + 5, state + 2)
        # loop variables that are never written keep one cell for the whole
        # loop (lua only needs a fresh one when the body can change it)
        for var in s["vars"]:
            if not self.forin_fresh.get(self.key_of(var), False):
                self.emit(OP_NEWCELL, self.localinfo[self.key_of(var)]["reg"])
        top = self.here()
        self.emit(OP_MOVE, state + 0, state + 3)
        self.emit(OP_MOVE, state + 1, state + 4)
        self.emit(OP_MOVE, state + 2, state + 5)
        # k, v = iter(st, ctrl)   (specialised call: no arg/result tables)
        self.emit(OP_FORCALL, state + 0)
        # keep the new control value for the next iteration (lua uses the
        # first result of the iterator as the next control variable)
        self.emit(OP_MOVE, state + 5, state + 0)
        jf = self.here()
        self.emit(OP_JMPF, state + 0, 0)
        for i, var in enumerate(s["vars"]):
            info = self.localinfo[self.key_of(var)]
            r = info["reg"]
            if self.forin_fresh.get(self.key_of(var), False):
                self.emit(OP_NEWCELL, r)
            self.emit(OP_SETCELL, r, state + 0 + i)
        self.breaks.append(None)
        bstart, cstart = len(self.breaks), len(self.continues)
        self.gen_block(s.get("body"))
        self.emit(OP_JMP, top - (self.here() + WIDTH))
        end = self.here()
        self.patch(jf, end, 2)
        for b in self.breaks[bstart:]:
            if b is not None:
                self.patch(b, end)
        del self.breaks[bstart:]
        for c in self.continues[cstart:]:
            if c is not None:
                self.patch(c, top)
        del self.continues[cstart:]

    def gen_compound(self, s):
        var = s["var"]
        opname = s.get("op", "Add")
        if opname not in BINARY_OPS:
            raise NotImplementedError("compound assignment %s" % opname)
        cur = self.gen_expr(var)
        rhs = self.gen_expr(s["value"])
        t = self.alloc_tmp()
        self.emit(BINARY_OPS[opname], t, cur, rhs)
        self.gen_store(var, t)

    # -- expressions -----------------------------------------------------

    def gen_expr(self, e):
        if not isinstance(e, dict):
            raise NotImplementedError("bad expression %r" % (e,))
        t = e.get("type")
        if t == "AstExprConstantNumber":
            r = self.alloc_tmp()
            v = e["value"]
            if isinstance(v, float) and v == int(v) and abs(v) < 2147483647:
                v = int(v)
            if isinstance(v, int) and not isinstance(v, bool) and abs(v) < 2147483647:
                self.emit(OP_NUM, r, v)
            else:
                self.emit(OP_CONST, r, self.p.add_number(v))
            return r
        if t == "AstExprConstantString":
            r = self.alloc_tmp()
            self.emit(OP_CONST, r, self.p.add_string(e["value"]))
            return r
        if t == "AstExprConstantTrue" or (t == "AstExprConstantBool" and e.get("value") is True):
            r = self.alloc_tmp()
            self.emit(OP_TRUE, r)
            return r
        if t == "AstExprConstantFalse" or (t == "AstExprConstantBool" and e.get("value") is False):
            r = self.alloc_tmp()
            self.emit(OP_FALSE, r)
            return r
        if t == "AstExprConstantNil":
            r = self.alloc_tmp()
            self.emit(OP_NIL, r)
            return r
        if t == "AstExprLocal":
            key = self.key_of(e["local"])
            info = self.localinfo[key]
            r = self.alloc_tmp()
            if info["func"] is not self.cur_func:
                # free variable: captured as an upvalue (which holds a cell)
                idx = self.cur_func.upval_index.get(key, 0)
                self.emit(OP_GETUPVAL, r, idx)
                r2 = self.alloc_tmp()
                self.emit(OP_GETCELL, r2, r)
                return r2
            elif info["boxed"]:
                self.emit(OP_GETCELL, r, info["reg"])
            else:
                self.emit(OP_MOVE, r, info["reg"])
            return r
        if t == "AstExprGlobal":
            r = self.alloc_tmp()
            self.emit(OP_GETGLOBAL, r, self.p.add_string(e["global"]))
            return r
        if t == "AstExprIndexName":
            base = self.gen_expr(e["expr"])
            r = self.alloc_tmp()
            self.emit(OP_GETFIELD, r, base, self.p.add_string(e["index"]))
            return r
        if t == "AstExprIndexExpr":
            base = self.gen_expr(e["expr"])
            key = self.gen_expr(e["index"])
            r = self.alloc_tmp()
            self.emit(OP_GETTABLE, r, base, key)
            return r
        if t == "AstExprGroup":
            return self.gen_expr(e["expr"])
        if t == "AstExprUnary":
            src = self.gen_expr(e["expr"])
            r = self.alloc_tmp()
            self.emit(UNARY_OPS[e["op"]], r, src)
            return r
        if t == "AstExprBinary":
            return self.gen_binary(e)
        if t == "AstExprCall":
            return self.gen_call(e)
        if t == "AstExprFunction":
            child = self.nodefunc[id(e)]
            r = self.alloc_tmp()
            self.emit(OP_CLOSURE, r, child.index)
            return r
        if t == "AstExprTable":
            return self.gen_table(e)
        if t == "AstExprVarargs":
            r = self.alloc_tmp()
            self.emit(OP_VARARG1, r)
            return r
        raise NotImplementedError("expression %s" % t)

    def gen_binary(self, e):
        op = e.get("op")
        if op == "And":
            left = self.gen_expr(e["left"])
            res = self.alloc_tmp()
            jf = self.here()
            self.emit(OP_JMPF, left, 0)
            right = self.gen_expr(e["right"])
            self.emit(OP_MOVE, res, right)
            jend = self.here()
            self.emit(OP_JMP, 0)
            self.patch(jf, self.here(), 2)
            self.emit(OP_MOVE, res, left)
            self.patch(jend, self.here())
            return res
        if op == "Or":
            left = self.gen_expr(e["left"])
            res = self.alloc_tmp()
            jt = self.here()
            self.emit(OP_JMPT, left, 0)
            right = self.gen_expr(e["right"])
            self.emit(OP_MOVE, res, right)
            jend = self.here()
            self.emit(OP_JMP, 0)
            self.patch(jt, self.here(), 2)
            self.emit(OP_MOVE, res, left)
            self.patch(jend, self.here())
            return res
        left = self.gen_expr(e["left"])
        right = self.gen_expr(e["right"])
        r = self.alloc_tmp()
        self.emit(BINARY_OPS[op], r, left, right)
        return r

    def gen_call_expand(self, e):
        """Compile a call whose results are collected in a fresh area.

        Returns (area_reg, count_reg).  At most eight results are kept, which
        covers every realistic lua call.
        """
        area = self.alloc_tmp(8)
        cnt = self.alloc_tmp(1)
        args = e.get("args", [])
        if e.get("self"):
            func = e["func"]
            base = self.gen_expr(func["expr"])
            r = self.alloc_tmp()
            self.alloc_tmp()
            self.emit(OP_SELF, r, base, self.p.add_string(func["index"]))
            argbase = r + 2
            n = 0
            for a in args:
                v = self.gen_expr(a)
                if v != argbase + n:
                    self.emit(OP_MOVE, argbase + n, v)
                n += 1
            self.emit(OP_CALLV, r, n + 1, area, cnt)
            return area, cnt
        base = self.gen_expr(e["func"])
        n = 0
        for a in args:
            v = self.gen_expr(a)
            if v != base + 1 + n:
                self.emit(OP_MOVE, base + 1 + n, v)
            n += 1
        self.emit(OP_CALLV, base, n, area, cnt)
        return area, cnt

    def gen_call(self, e, want=1):
        args = e.get("args", [])
        if e.get("self"):
            func = e["func"]
            base = self.gen_expr(func["expr"])
            r = self.alloc_tmp()
            self.alloc_tmp()          # reserve r+1 for the receiver
            self.emit(OP_SELF, r, base, self.p.add_string(func["index"]))
            argbase = r + 2
            n = 0
            for a in args:
                v = self.gen_expr(a)
                if v != argbase + n:
                    self.emit(OP_MOVE, argbase + n, v)
                n += 1
            self.emit(OP_CALL, r, n + 1, want)
            return r
        base = self.gen_expr(e["func"])
        # a trailing call expands to all of its results
        if args and self.is_call(args[-1]):
            n = 0
            for a in args[:-1]:
                v = self.gen_expr(a)
                if v != base + 1 + n:
                    self.emit(OP_MOVE, base + 1 + n, v)
                n += 1
            area, cnt = self.gen_call_expand(args[-1])
            self.emit(OP_CALLX, base, n, area, cnt)
            return base
        n = 0
        for a in args:
            v = self.gen_expr(a)
            if v != base + 1 + n:
                self.emit(OP_MOVE, base + 1 + n, v)
            n += 1
        self.emit(OP_CALL, base, n, want)
        return base

    def gen_table(self, e):
        r = self.alloc_tmp()
        self.emit(OP_NEWTABLE, r, 0)
        idx = 1
        items = e.get("items", [])
        # `{...}` collects every vararg
        if len(items) == 1 and items[0].get("kind") == "item" and \
                items[0].get("value", {}).get("type") == "AstExprVarargs":
            self.emit(OP_VARARGTABLE, r)
            return r
        for item in items:
            kind = item.get("kind")
            if kind == "item":
                v = self.gen_expr(item["value"])
                self.emit(OP_SETLIST, r, idx, v)
                idx += 1
            elif kind == "record":
                v = self.gen_expr(item["value"])
                self.emit(OP_SETTABLEK, r, v, self.p.add_string(item["key"]["value"]))
            else:
                kv = self.gen_expr(item["key"])
                v = self.gen_expr(item["value"])
                self.emit(OP_SETTABLE, r, kv, v)
        return r
