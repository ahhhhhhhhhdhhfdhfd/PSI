import os
import random
import re

from . import compiler as C
from . import encoder as E

HEADER = "-- This file was protected using PSI Obfuscator"

VM_NAMES = [
    "table.unpack", "table.pack",                      # 0, 1
    "math.floor", "math.max", "math.min",              # 2, 3, 4
    "string.sub", "string.format", "string.rep",       # 5, 6, 7
    "rawequal", "select", "tonumber", "tostring",     # 8 .. 11
    "type", "pcall", "error", "getmetatable",          # 12 .. 15
    "debug.info", "pairs", "assert", "print",          # 16 .. 19
    "warn", "ipairs", "next", "xpcall",                # 20 .. 23
    "setmetatable", "rawget", "rawset",                # 24 .. 26
    "getfenv", "setfenv", "loadstring", "unpack",      # 27 .. 30
    "os.clock",                                        # 31
]

# standard library functions that must still be the native ones
PROBE_NAMES = [
    "print", "warn", "type", "tostring", "tonumber", "pairs", "ipairs", "next",
    "select", "error", "assert", "pcall", "xpcall", "setmetatable",
    "getmetatable", "rawget", "rawset", "getfenv", "setfenv", "loadstring",
    "unpack", "os.clock",
    # the usual hooking helpers - if one of them is not native anymore the
    # environment has been tampered with
    "getgenv", "getrenv", "hookfunction", "hookmetamethod", "setreadonly",
    "isreadonly", "getrawmetatable", "setclipboard", "getupvalue",
    "setupvalue", "newproxy", "require", "load", "collectgarbage",
    "debug.traceback", "debug.getinfo", "string.dump", "coroutine.create",
    # New advanced anti-tamper probes
    "Random.new", "Random:NextInteger", "Random:NextNumber", "Random:Clone",
    "task.spawn", "task.defer", "task.delay", "task.wait", "task.cancel",
    "Enum.HumanoidStateType.FromName", "Enum.HumanoidStateType.FromValue",
    "Instance.new", "Instance.IsA", "Instance.Destroy", "Instance.GetChildren",
    "buffer.create", "buffer.readu8", "buffer.writeu8", "buffer.copy", "buffer.fill",
    "coroutine.create", "coroutine.resume", "coroutine.yield",
    "Drawing.new", "getrenderproperty", "setrenderproperty", "isrenderobj",
    "rawgetmetatable", "iscclosure", "getscriptclosure", "getgenv", "getrenv",
    "hookfunction", "hookmetamethod", "newcclosure", "isreadonly", "setreadonly",
    "getrawmetatable", "setrawmetatable", "getupvalue", "setupvalue",
]

# metamethod names - a global with one of those prefixes is not an injection
META_NAMES = [
    "__index", "__newindex", "__name", "__tostring", "__call", "__len", "__eq",
    "__lt", "__le", "__concat", "__close", "__mode", "__metatable", "__pairs",
    "__ipairs", "__gc", "__id", "__add", "__sub", "__mul", "__div", "__mod",
    "__pow", "__unm", "__idiv", "__band", "__bor", "__bxor", "__bnot", "__shl",
    "__shr", "__type", "__ncl",
]

MIN_PAYLOAD_SIZE = 100 * 1024        # 100 KB
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024   # 5 MB

FIELD_TOKENS = {
    "SEED": "@@F0@@", "PLEN": "@@F1@@", "SLEN": "@@F2@@", "CFL": "@@F3@@",
    "PHASH": "@@F4@@", "NCAN": "@@F5@@", "NWIN": "@@F6@@", "STRH": "@@F7@@",
    "LIB0": "@@F8@@", "PRB0": "@@F9@@", "MTB0": "@@F10@@", "WHASH": "@@F11@@",
    "PROGBASE": "@@F12@@", "STRBASE": "@@F13@@", "NCAN2": "@@F14@@",
}



def long_bracket(data):
    """Wrap binary data in a Lua long string, picking a safe '=' level."""
    level = 0
    while True:
        closing = b"]" + b"=" * level + b"]"
        if closing not in data:
            break
        level += 1
    eq = b"=" * level
    return b"[" + eq + b"[" + data + b"]" + eq + b"]"


def _is_word(ch):
    return ch.isalnum() or ch == "_"


def minify_lua(src):
    """Strip redundant whitespace from generated lua (string literals are kept
    verbatim).  The result stays valid lua and is a single line."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = src[i]
                out.append(c)
                i += 1
                if c == "\\" and i < n:
                    out.append(src[i])
                    i += 1
                elif c == quote:
                    break
            continue
        if ch == "[":
            # long bracket string: [==[ ... ]==]
            j = i + 1
            eqs = 0
            while j < n and src[j] == "=":
                eqs += 1
                j += 1
            if j < n and src[j] == "[":
                closer = "]" + ("=" * eqs) + "]"
                out.append(src[i:j + 1])
                end = src.find(closer, j + 1)
                if end < 0:
                    out.append(src[j + 1:])
                    i = n
                else:
                    out.append(src[j + 1:end])
                    out.append(closer)
                    i = end + len(closer)
                continue
        if ch.isspace():
            j = i
            while j < n and src[j].isspace():
                j += 1
            if out and j < n:
                prev = out[-1]
                nxt = src[j]
                if _is_word(prev[-1]) and _is_word(nxt):
                    out.append(" ")
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)

def make_opmap(rng, junk=True):
    """Assign a random number to every opcode (per build)."""
    ops = list(C.ALL_OPS)
    nums = list(range(1, len(ops) + 1))
    rng.shuffle(nums)
    return dict(zip(ops, nums))


HANDLERS = {
    C.OP_MOVE: "R[a]=R[b]",
    C.OP_CONST: "R[a]=K(b)",
    C.OP_NUM: "R[a]=b",
    C.OP_NIL: "R[a]=nil",
    C.OP_TRUE: "R[a]=true",
    C.OP_FALSE: "R[a]=false",
    C.OP_GETGLOBAL: "R[a]=ENV[K(b)]",
    C.OP_SETGLOBAL: "ENV[K(b)]=R[a]",
    C.OP_GETTABLE: "R[a]=R[b][R[c]]",
    C.OP_SETTABLE: "R[a][R[b]]=R[c]",
    C.OP_GETFIELD: "R[a]=R[b][K(c)]",
    C.OP_SETFIELD: "R[a][K(c)]=R[b]",
    C.OP_SETTABLEK: "R[a][K(c)]=R[b]",
    C.OP_NEWTABLE: "R[a]={}",
    C.OP_SETLIST: "R[a][b]=R[c]",
    C.OP_ADD: "R[a]=R[b]+R[c]",
    C.OP_SUB: "R[a]=R[b]-R[c]",
    C.OP_MUL: "R[a]=R[b]*R[c]",
    C.OP_DIV: "R[a]=R[b]/R[c]",
    C.OP_IDIV: "R[a]=FL(R[b]/R[c])",
    C.OP_MOD: "R[a]=R[b]%R[c]",
    C.OP_POW: "R[a]=R[b]^R[c]",
    C.OP_CONCAT: "R[a]=R[b]..R[c]",
    C.OP_LT: "R[a]=R[b]<R[c]",
    C.OP_LE: "R[a]=R[b]<=R[c]",
    C.OP_GT: "R[a]=R[b]>R[c]",
    C.OP_GE: "R[a]=R[b]>=R[c]",
    C.OP_EQ: "R[a]=R[b]==R[c]",
    C.OP_NE: "R[a]=R[b]~=R[c]",
    C.OP_NOT: "R[a]=not R[b]",
    C.OP_NEG: "R[a]=-R[b]",
    C.OP_LEN: "R[a]=#R[b]",
    C.OP_JMP: "pc=pc+a",
    C.OP_JMPF: "if not R[a] then pc=pc+b end",
    C.OP_JMPT: "if R[a] then pc=pc+b end",
    C.OP_CALL: """local f=R[a]
local nb=b
if c==1 then
if nb==0 then R[a]=f()
elseif nb==1 then R[a]=f(R[a+1])
elseif nb==2 then R[a]=f(R[a+1],R[a+2])
else
local ar={}
for i=1,nb do ar[i]=R[a+i] end
R[a]=f(UP(ar,1,nb))
end
R[RES]=1
else
local ar={}
for i=1,nb do ar[i]=R[a+i] end
local res=TP(docall(f,ar,nb))
local cn=res.n
for i=1,cn do R[a+i-1]=res[i] end
R[RES]=cn
if cn>c then cn=c end
for i=cn+1,c do R[a+i-1]=nil end
end""",
    C.OP_ENTERLVL: "return call(a,{},{})",
    C.OP_FORCALL: """local f=R[a]
local x,y=f(R[a+1],R[a+2])
R[a]=x
R[a+1]=y""",
    C.OP_CALLV: """local f=R[a]
local nb=b
local ar={}
for i=1,nb do ar[i]=R[a+i] end
local cnt
local function pk(...)
cnt=select("#",...)
for i=1,cnt do
if i<=8 then R[c+i-1]=select(i,...) end
end
end
pk(docall(f,ar,nb))
R[d]=cnt""",
    C.OP_CALLX: """local f=R[a]
local nb=b
local n=R[d]
local ar={}
for i=1,nb do ar[i]=R[a+i] end
for i=1,n do ar[nb+i]=R[c+i-1] end
local res=TP(docall(f,ar,nb+n))
local cn=res.n
for i=1,cn do R[a+i-1]=res[i] end
R[RES]=cn""",
    C.OP_RET: """local cn=b
if b<0 then cn=R[RES] end
local rr={}
for i=0,cn-1 do rr[i+1]=R[a+i] end
return UP(rr,1,cn)""",
    C.OP_CLOSURE: """local upv=PROTOS[b][5]
local uv={}
for i=1,#upv do
local kk=upv[i][1]
local xx=upv[i][2]
if kk==0 then uv[i]=R[xx] else uv[i]=U[xx] end
end
R[a]=function(...)
local ar={...}
return call(b,ar,uv)
end""",
    C.OP_GETUPVAL: "R[a]=U[b]",
    C.OP_SETUPVAL: "U[b][1]=R[a]",
    C.OP_NEWCELL: "R[a]={}",
    C.OP_GETCELL: "R[a]=R[b][1]",
    C.OP_SETCELL: "R[a][1]=R[b]",
    C.OP_VARARG1: "R[a]=V[1]",
    C.OP_VARARGTABLE: """local t={}
for i=1,#V do t[i]=V[i] end
R[a]=t""",
    C.OP_FORCOND: "R[a]=(R[d]>0 and R[b]<=R[c]) or (R[d]<0 and R[b]>=R[c])",
    C.OP_SELF: "R[a]=R[b][K(c)]\nR[a+1]=R[b]",
    C.OP_JUNK: "",
}


def build_dispatch(opmap, indent="    "):
    """Binary dispatch tree over the randomised opcode numbers."""
    items = sorted((opmap[op], HANDLERS[op]) for op in C.ALL_OPS)

    def gen(lst, pad):
        if len(lst) == 1:
            num, body = lst[0]
            lines = ["%sif op==%d then" % (pad, num)]
            if body:
                for ln in body.split("\n"):
                    lines.append((pad + "\t" + ln) if ln else "")
            lines.append("%send" % pad)
            return lines
        mid = len(lst) // 2
        left, right = lst[:mid], lst[mid:]
        pivot = right[0][0]
        lines = ["%sif op<%d then" % (pad, pivot)]
        lines.extend(gen(left, pad + "\t"))
        lines.append("%selse" % pad)
        lines.extend(gen(right, pad + "\t"))
        lines.append("%send" % pad)
        return lines

    return "\n".join(gen(items, indent))

VM_BODY = r"""
local P=self
local DATA=P[@@KB@@]
local NP=@@NOP@@

local CH=("").char
local ENV=(getfenv and getfenv(1)) or _G

-- the first 64 symbols of the data field are the alphabet of this build, the
-- rest is the encrypted program
local SYM={}
local START=1
do
local i=1
local k=0
while k<64 do
local c=DATA:byte(i)
local l=1
if c>=240 then l=4 elseif c>=224 then l=3 elseif c>=192 then l=2 end
SYM[DATA:sub(i,i+l-1)]=k
k=k+1
i=i+l
end
START=i
end

local function b64dec(s,from)
local out={}
local acc=0
local bits=0
local i=from
local n=#s
while i<=n do
local c=s:byte(i)
local l=1
if c>=240 then l=4 elseif c>=224 then l=3 elseif c>=192 then l=2 end
local v=SYM[s:sub(i,i+l-1)]
if v then
acc=acc*64+v
bits=bits+6
if bits>=8 then
bits=bits-8
local d=2^bits
local q=acc/d
local byte=q-q%1
acc=acc-byte*d
out[#out+1]=byte
end
end
i=i+l
end
return out
end

local raw=b64dec(DATA,START)

__DEC__

local function uncomp(s)
local out={}
local i=1
local n=#s
while i<=n do
local k=s[i]
i=i+1
if k==0 then
local c=s[i]
i=i+1
for j=1,c do
out[#out+1]=s[i]
i=i+1
end
else
local l=s[i]
local d=s[i+1]+s[i+2]*256
i=i+3
local st=#out-d+1
for j=1,l do
out[#out+1]=out[st+j-1]
end
end
end
return out
end

local function rdu32(t,off)
return t[off]+t[off+1]*256+t[off+2]*65536+t[off+3]*16777216
end

__HEADER__
local @@F13@@=@@F12@@+@@F1@@
local PB
if @@F3@@==1 then
PB=uncomp(dec(raw,@@F12@@,@@F1@@,@@F0@@))
else
PB=dec(raw,@@F12@@,@@F1@@,@@F0@@)
end

local pos=1
local function rdint()
local v=PB[pos]+PB[pos+1]*256+PB[pos+2]*65536+PB[pos+3]*16777216
if v>=2147483648 then v=v-4294967296 end
pos=pos+4
return v
end

local NPROTO=rdint()
local NSTR=rdint()
local PROTOS={}
for i=1,NPROTO do
local nparams=rdint()
local nregs=rdint()
local nlocals=rdint()
local vararg=rdint()
local nup=rdint()
local clen=rdint()
local lkey=rdint()
local sled=rdint()
local code={}
for j=1,clen do code[j]=rdint() end
if sled>0 then
setmetatable(code,{__index=function(t,i)
if i>clen and i<=clen+sled then return NP end
return nil
end})
end
local upv={}
for j=1,nup do
local kk=rdint()
local xx=rdint()
upv[j]={kk,xx}
end
PROTOS[i-1]={code,nregs,nparams,vararg,upv,false,lkey,sled}
end
local SOFF={}
local SLEN2={}
for i=1,NSTR do
SOFF[i]=rdint()
SLEN2[i]=rdint()
end
local @@F14@@=@@F5@@
local CANI={}
local CANV={}
for i=1,@@F14@@ do
CANI[i]=rdint()
CANV[i]=rdint()
end

local SCACHE={}
local function mkstr(t,from,to)
local s=""
local i=from
local n=to
while i<=n do
local j=i+63
if j>n then j=n end
local c=""
for k=i,j do c=c..CH(t[k]) end
s=s..c
i=j+1
end
return s
end

local function K(i)
local v=SCACHE[i]
if v~=nil then return v end
local sd=__STRSEED__
local s=dec(raw,@@F13@@+SOFF[i],SLEN2[i],sd)
if s[1]==1 then v=tonumber(mkstr(s,2,#s)) else v=mkstr(s,2,#s) end
SCACHE[i]=v
return v
end

local RCACHE={}
local function resolve(idx,fresh)
if not fresh then
local cached=RCACHE[idx]
if cached~=nil then
if cached==false then return nil end
return cached
end
end
local name=K(idx)
local v=ENV
local i=1
local n=#name
local cur=""
while i<=n do
local b=name:byte(i)
if b==46 then
if cur~="" then
local ok,nv=pcall(function() return v[cur] end)
if not ok or nv==nil then
if not fresh then RCACHE[idx]=false end
return nil
end
v=nv
cur=""
end
else
cur=cur..CH(b)
end
i=i+1
end
if cur~="" then
local ok,nv=pcall(function() return v[cur] end)
if not ok or nv==nil then
if not fresh then RCACHE[idx]=false end
return nil
end
v=nv
end
if not fresh then RCACHE[idx]=v end
return v
end

local UP=resolve(@@F8@@) or resolve(@@F8@@+29)
local TP=resolve(@@F8@@+1)

local call,docall
docall=function(f,ar,n)
if type(f)=="table" and f.v then
return call(f.p,ar,f.u)
end
return f(UP(ar,1,n))
end

call=function(pi,args,upvals)
local pr=PROTOS[pi]
local code=pr[1]
if not pr[6] then
local kk=pr[7]
for i=1,#code,5 do code[i]=__OPKEY__ end
pr[6]=true
end
local nregs=pr[2]
local nparams=pr[3]
local R={}
for i=0,nparams-1 do R[i]=args[i+1] end
local U=upvals
local V=args
local RES=nregs
local pc=1
local GUARD=0
local GUARDIDX=0
while true do
local op=code[pc]
if op<1 or op>@@OPMAX@@ then __OPFAIL__ end
local a=code[pc+__SA__]
local b=code[pc+__SB__]
local c=code[pc+__SC__]
local d=code[pc+__SD__]
pc=pc+5
GUARD=GUARD+1
__GUARDBLOCK__
__DISPATCH__
end
end

local MAIN=NPROTO-1
local function run(...)
local args={...}
local n=#args
local a={}
for i=1,n do a[i]=args[i] end
local ok,res=pcall(function()
if @@H9@@ then @@H9@@() end
return call(MAIN,a,{})
end)
if not ok then
if res~=@@V1@@ then error(res,0) end
return nil
end
return res
end
return run(...)
"""

TRAP = r"""
__HASH__

local @@V2@@=2166136261
local @@V1@@={}
local function @@H2@@()
if @@DEBUG_TRAP@@ then print('TRAP', debug.traceback()) end
@@V2@@=(@@V2@@*65599+1)%4294967296
-- scramble all protos
for i=0,NPROTO-1 do
local p=PROTOS[i]
for j=1,#p[1] do p[1][j]=(p[1][j]*65599+@@V2@@)%4294967296 end
end
-- clear string cache
local pr=resolve(@@F8@@+17)
if pr then
for k in pr(SCACHE) do SCACHE[k]=nil end
for k in pr(RCACHE) do RCACHE[k]=nil end
end
-- wipe upvalues
for i=0,NPROTO-1 do
local p=PROTOS[i]
if p[5] then
for j=1,#p[5] do p[5][j]=nil end
end
end
-- corrupt the dispatch
for i=1,#code do code[i]=0 end
error(@@V1@@,0)
end

local function @@H3@@()
local inf=resolve(@@F8@@+16,true)
local mt=resolve(@@F8@@+12,true)
if mt(inf)~="function" then return true end
for i=0,@@PRBN@@-1 do
local f=resolve(@@F9@@+i,true)
if mt(f)=="function" then
local ok,info=pcall(inf,f,"s")
if ok and mt(info)=="string" and info~="[C]" and info~="" then return false end
-- also check that debug.info returns consistent results
local ok2,info2=pcall(inf,f,"n")
if ok2 and type(info2)=="number" and info2<0 then return false end
end
end
-- check that debug.getinfo (if available) is also native
local gi=resolve(@@F8@@+16,true)
if type(gi)=="function" then
local ok3,info3=pcall(gi,gi,"s")
if ok3 and type(info3)=="string" and info3~="[C]" and info3~="" then return false end
end
return true
end

local function @@H4@@()
local mt=resolve(@@F8@@+12,true)
local fl=resolve(@@F8@@+2,true)
local mx=resolve(@@F8@@+3,true)
local mn=resolve(@@F8@@+4,true)
local sb=resolve(@@F8@@+5,true)
local sf=resolve(@@F8@@+6,true)
local rp=resolve(@@F8@@+7,true)
local rq=resolve(@@F8@@+8,true)
local sl=resolve(@@F8@@+9,true)
local tn=resolve(@@F8@@+10,true)
local ts=resolve(@@F8@@+11,true)
local pc=resolve(@@F8@@+13,true)
if mt("")~="string" then return false end
if mt(1)~="number" then return false end
if mt({})~="table" then return false end
if mt(nil)~="nil" then return false end
if #"ab"~=2 then return false end
if ts(12)~="12" then return false end
if tn("12")~=12 then return false end
if sl("#",1,2)~=2 then return false end
if fl(1.5)~=1 then return false end
if mx(1,2)~=2 then return false end
if mn(1,2)~=1 then return false end
if sb("abc",2,2)~="b" then return false end
if sf("%d",7)~="7" then return false end
if rp("x",2)~="xx" then return false end
local t={} t[1]=5 if t[1]~=5 then return false end
local u={} u.x=1 if u.x~=1 then return false end
if ("x")~="x" then return false end
if rq({},{}) then return false end
local okp=pc(function() error("x",0) end)
if okp then return false end
-- check math constants
if type(math)=="table" then
if type(math.pi)~="number" or math.pi<3.14 or math.pi>3.15 then return false end
if type(math.huge)~="number" then return false end
end
-- check string library completeness
if type(string)=="table" then
if type(string.char)~="function" then return false end
if type(string.byte)~="function" then return false end
if type(string.format)~="function" then return false end
if type(string.rep)~="function" then return false end
if type(string.sub)~="function" then return false end
if type(string.len)~="function" then return false end
if type(string.upper)~="function" then return false end
if type(string.lower)~="function" then return false end
end
-- check table library completeness
if type(table)=="table" then
if type(table.insert)~="function" then return false end
if type(table.remove)~="function" then return false end
if type(table.concat)~="function" then return false end
if type(table.sort)~="function" then return false end
end
-- check that string.dump is not available (Roblox/Luau security)
if type(string)=="table" and type(string.dump)=="function" then return false end
-- check that loadstring returns native functions
local ls=resolve(@@F8@@+28,true)
if type(ls)=="function" then
local okl,fn=pcall(ls,"return 1")
if okl and type(fn)=="function" then
local oki,info=pcall(inf,fn,"s")
if oki and type(info)=="string" and info~="[C]" and info~="" then return false end
end
end
return true
end

local function @@H5@@()
local mt=resolve(@@F8@@+12)
local pr=resolve(@@F8@@+17)
if mt(ENV)~="table" then return false end
for k in pr(ENV) do
if mt(k)=="string" and k:sub(1,2)=="__" then
local ok=false
for i=0,@@MTBN@@-1 do
if K(@@F10@@+i)==k then ok=true break end
end
if not ok then return false end
-- a metamethod that lives in the environment as a function is always an
-- injection (a normal environment never has one)
if mt(ENV[k])=="function" then return false end
-- check for common exploit globals
if k=="getgenv" or k=="getrenv" or k=="getreg" or k=="getgc" then
if ENV[k]~=nil then return false end
end
if k=="hookfunction" or k=="hookmetamethod" or k=="newcclosure" then
if ENV[k]~=nil then return false end
end
if k=="readfile" or k=="writefile" or k=="appendfile" or k=="listfiles" then
if ENV[k]~=nil then return false end
end
if k=="getrawmetatable" or k=="setrawmetatable" or k=="getnamecallmethod" then
if ENV[k]~=nil then return false end
end
-- deobfuscator / anti analysis markers must never live in the env
if k=="Unveilr" or k=="unveilr" or k=="deobfuscate" or k=="deobf" or k=="unveil" or k=="moonsec" or k=="dlp1" or k=="dlp2" then
if ENV[k]~=nil then return false end
end
if k=="__unveilr" or k=="__deobf" or k=="__deobfuscate" or k=="__moonsec" or k=="__dlp1" or k=="__dlp2" then
if ENV[k]~=nil then return false end
end
end
end
return true
end

local function @@H6@@()
local mt=resolve(@@F8@@+12)
local gm=resolve(@@F8@@+15)
if mt(ENV)~="table" then return false end
local ok,m=pcall(gm,ENV)
if not ok or mt(m)~="table" then return true end
local mi=m[K(@@F10@@)]
if mt(mi)=="function" then return false end
-- check __newindex
local mn=m[K(@@F10@@+1)]
if mt(mn)=="function" then return false end
-- check __call
local mc=m[K(@@F10@@+4)]
if mt(mc)=="function" then return false end
-- check __tostring
local mts=m[K(@@F10@@+6)]
if mt(mts)=="function" then return false end
-- check __len
local ml=m[K(@@F10@@+5)]
if mt(ml)=="function" then return false end
-- check __eq
local me=m[K(@@F10@@+7)]
if mt(me)=="function" then return false end
-- check __gc
local mg=m[K(@@F10@@+16)]
if mt(mg)=="function" then return false end
return true
end

local function @@H7@@()
for i=1,@@F14@@ do
local o=CANI[i]*4+1
local v=PB[o]+PB[o+1]*256+PB[o+2]*65536+PB[o+3]*16777216
if v>=2147483648 then v=v-4294967296 end
if v~=CANV[i] then return false end
end
return true
end

local WOFF={}
do
local total=#PB
local n=@@F6@@
if n>0 then
if total<=64 then
for i=1,n do WOFF[i]=0 end
else
for i=1,n do WOFF[i]=(i-1)*(total-64)//(n-1) end
end
end
end
local function @@H8@@(i)
if @@F6@@<1 then return true end
local off=WOFF[i] or 0
return @@H1@@(PB,off+1,64)==@@F11@@[i]
end

local function @@H9@@()
if @@H1@@(raw,1,@@F13@@+@@F2@@-1)~=rdu32(raw,@@F13@@+@@F2@@) then @@H2@@() end
if @@H1@@(PB)~=(@@F4@@+4294967296-@@F0@@)%4294967296 then @@H2@@() end
if @@F2@@>0 and @@H1@@(raw,@@F13@@,@@F2@@)~=@@F7@@ then @@H2@@() end
if not @@H3@@() then @@H2@@() end
if not @@H4@@() then @@H2@@() end
if not @@H7@@() then @@H2@@() end
if not @@H5@@() then @@H2@@() end
if not @@H6@@() then @@H2@@() end
if not @@H8@@(1) then @@H2@@() end
end

-- ============================================================
-- ADVANCED ANTI-TAMPER CHECKS
-- ============================================================

local function @@H10@@() -- Anti-beautify / self-integrity
local mt=resolve(@@F8@@+12,true)
local inf=resolve(@@F8@@+16,true)
if mt(inf)~="function" then return true end
-- Verify our own source hasn't been beautified/modified
local ok,src=pcall(inf,@@H10@@,"s")
if ok and type(src)=="string" then
if src:find("%s%s") or src:find("
%s*
") then return false end
end
return true
end

local function @@H11@@() -- Anti-hook: verify native function metadata
local inf=resolve(@@F8@@+16,true)
local mt=resolve(@@F8@@+12,true)
if mt(inf)~="function" then return true end
local natives={
pcall,"pcall",xpcall,"xpcall",tostring,"tostring",tonumber,"tonumber",
type,"type",typeof,"typeof",rawequal,"rawequal",rawget,"rawget",
rawset,"rawset",getmetatable,"getmetatable",setmetatable,"setmetatable",
select,"select",error,"error",assert,"assert",
string.byte,"byte",string.sub,"sub",string.char,"char",
bit32.bxor,"bxor",buffer.create,"create",debug.info,"info",
debug.traceback,"traceback",coroutine.resume,"resume",
game.GetService,"GetService",Instance.new,"new"
}
for i=1,#natives,2 do
local fn=natives[i]
local expected=natives[i+1]
if type(fn)~="function" then return false end
local s,l,n,a,v,f=debug.info(fn,"slnaf")
if s~="[C]" or l~=-1 or n~=expected or a~=0 or v~=true then return false end
end
return true
end

local function @@H12@@() -- Random deterministic stream check
if type(Random)~="function" then return true end
local r1=Random.new(1515359100)
local expected={763,0.52705833430898807,0.44671507908619318,397,847,0.61786750792918488,788,81,0.37417195152223198,1008}
local actual={
r1:NextInteger(532,1117),r1:NextNumber(),r1:NextNumber(),r1:NextInteger(299,786),
r1:NextInteger(784,1062),r1:NextNumber(),r1:NextInteger(695,1094),
r1:NextInteger(30,107),r1:NextNumber(),r1:NextInteger(999,1013)
}
for i=1,#expected do if actual[i]~=expected[i] then return false end end
local clone=r1:Clone()
if clone:NextInteger(-1000000,1000000)~=r1:NextInteger(-1000000,1000000) then return false end
if clone:NextNumber()~=r1:NextNumber() then return false end
return true
end

local function @@H13@@() -- Task closure metadata
local inf=resolve(@@F8@@+16,true)
if type(inf)~="function" then return true end
local task_funcs={"spawn","defer","delay","wait","cancel"}
for _,name in ipairs(task_funcs) do
local fn=task and task[name]
if type(fn)~="function" then return false end
local s,l,n=debug.info(fn,"sln")
if s~="[C]" or l~=-1 or n~=name then return false end
end
return true
end

local function @@H14@@() -- Enum behavior check
if type(Enum)~="table" then return true end
local enumType=Enum.HumanoidStateType
if type(enumType)~="table" then return true end
if type(enumType.FromName)~="function" or type(enumType.FromValue)~="function" then return false end
if rawequal(enumType.FromName,enumType.FromName) then return false end
if rawequal(enumType.FromValue,enumType.FromValue) then return false end
if enumType:FromName("X")~=nil then return false end
if enumType:FromValue(0)~=Enum.HumanoidStateType.FallingDown then return false end
return true
end

local function @@H15@@() -- Instance lifecycle check
if type(Instance)~="table" or type(Instance.new)~="function" then return true end
local folder=Instance.new("Folder")
if not folder then return false end
if not folder.IsA then return false end
folder.Name="PSI_AntiEnv"
folder:Destroy()
if folder.Parent~=nil then return false end
if folder.Name~="PSI_AntiEnv" then return false end
return true
end

local function @@H16@@() -- Buffer and coroutine surface
if type(buffer)~="table" then return true end
local buf_names={"create","fromstring","tostring","len","readu8","readu16",
"readi16","readi32","readu32","readf32","readf64","readstring",
"writeu8","writeu16","writei16","writei32","writeu32","writef32",
"writef64","writestring","fill","copy"}
for _,name in ipairs(buf_names) do if type(buffer[name])~="function" then return false end end
local bytes=buffer.create(40)
buffer.writeu8(bytes,0,0xFE)
buffer.writeu16(bytes,1,0xBEEF)
buffer.writei16(bytes,3,-1234)
buffer.writei32(bytes,5,-123456789)
buffer.writeu32(bytes,9,0x89ABCDEF)
buffer.writef32(bytes,13,1.5)
buffer.writef64(bytes,17,math.pi)
buffer.writestring(bytes,25,"PSI}")
if buffer.len(bytes)~=40 then return false end
if buffer.readu8(bytes,0)~=0xFE then return false end
if buffer.readu16(bytes,1)~=0xBEEF then return false end
if buffer.readi16(bytes,3)~=-1234 then return false end
if buffer.readi32(bytes,5)~=-123456789 then return false end
if buffer.readu32(bytes,9)~=0x89ABCDEF then return false end
if math.abs(buffer.readf32(bytes,13)-1.5)>0.0001 then return false end
if math.abs(buffer.readf64(bytes,17)-math.pi)>0.0000001 then return false end
if buffer.readstring(bytes,25,4)~="PSI}" then return false end
if type(coroutine)~="table" then return true end
for _,name in ipairs({"close","isyieldable","running","status","create","resume","yield"}) do
if type(coroutine[name])~="function" then return false end
end
return true
end

local function @@H17@@() -- Drawing-based anti-tamper (Roblox)
local ok,draw=pcall(function() return Drawing and Drawing.new end)
if not ok or type(draw)~="function" then return true end
local square=draw("Square")
if not square then return false end
pcall(function() square.Visible=true end)
pcall(function() square.Size=Vector2.new(40,25) end)
local sz=pcall(function() return getrenderproperty(square,"Size") end)
local vis=pcall(function() return getrenderproperty(square,"Visible") end)
local live=pcall(function() return isrenderobj(square) and square.__OBJECT_EXISTS==true end)
pcall(function() square:Destroy() end)
if not (sz and vis and live) then return false end
return true
end

local function @@H18@@() -- Executor metatable boundary
local env=type(getgenv)=="function" and getgenv() or getfenv(0)
local rawmt=env.getrawmetatable
if type(rawmt)~="function" then return true end
local mt=rawmt(game)
if type(mt)~="table" then return false end
if not rawequal(mt.__index(game,"Workspace"),workspace) then return false end
local isc=env.iscclosure
if type(isc)=="function" then
if not isc(mt.__index) then return false end
if not isc(mt.__namecall) then return false end
end
local gsc=env.getscriptclosure
if type(gsc)=="function" then
local scr=Instance.new("LocalScript")
local res=gsc(scr)
scr:Destroy()
if res~=nil then return false end
end
return true
end

local function @@H19@@() -- Anti-env logger: fake global trap
local env=type(getgenv)=="function" and getgenv() or getfenv(0)
local mt=getmetatable(env)
if mt and type(mt)=="table" then
if type(mt.__index)=="function" then return false end
if type(mt.__newindex)=="function" then return false end
end
-- Check for common env logger globals
local logger_globals={"α","β","γ","δ","ε","ζ","η","θ","ι","κ","λ","μ","ν","ξ","ο","π","ρ","σ","τ","υ","φ","χ","ψ","ω","αβ","αγ","αδ","αε","αζ","αη","αθ","αι","ακ","αλ","αμ","αν","αξ","αο","απ","αρ","ασ","ατ","αυ","αφ","αχ","αψ","αω","βα","ββ","βγ","βδ","βε","βζ","βη","βθ","βι","βκ","βλ","βμ","βν","βξ","βο","βπ","βρ","βσ","βτ","βυ","βφ","βχ","βψ","βω"}
for _,name in ipairs(logger_globals) do
if rawget(env,name)~=nil then return false end
end
return true
end

local function @@H20@@() -- Debug info self-consistency
local inf=resolve(@@F8@@+16,true)
if type(inf)~="function" then return true end
-- Check that debug.info on itself returns [C]
local ok,s=pcall(inf,inf,"s")
if ok and type(s)=="string" and s~="[C]" then return false end
-- Check that debug.info on a known native returns [C]
local ok2,s2=pcall(inf,print,"s")
if ok2 and type(s2)=="string" and s2~="[C]" then return false end
return true
end

local function @@H21@@() -- Anti-beautify: string constant integrity
local str="PSI_INTEGRITY_CHECK_"..tostring(os.clock())
if str:find("%s%s") then return false end
if #str<20 then return false end
return true
end

local function @@H22@@() -- Timing check against VM hooking
local t0=os.clock()
local sum=0
for i=1,10000 do sum=sum+i end
local dt=os.clock()-t0
if dt>0.1 then return false end -- Too slow = hooked/debugger
return true
end

local function @@H23@@() -- Metatable trap detection
local env=type(getgenv)=="function" and getgenv() or getfenv(0)
local mt=getmetatable(env)
if mt and type(mt)=="table" then
-- Check for proxy metamethods
if type(mt.__index)=="function" then return false end
if type(mt.__newindex)=="function" then return false end
if type(mt.__call)=="function" then return false end
if type(mt.__metatable)~=nil then return false end -- Protected metatable = suspicious
end
-- Also check _G
local gmt=getmetatable(_G)
if gmt and type(gmt)=="table" then
if type(gmt.__index)=="function" then return false end
if type(gmt.__newindex)=="function" then return false end
end
return true
end

local function @@H24@@() -- Fake function detection
local inf=resolve(@@F8@@+16,true)
if type(inf)~="function" then return true end
-- Test that a freshly created function is not [C]
local testfn=function() return 42 end
local ok,s=pcall(inf,testfn,"s")
if ok and type(s)=="string" and s=="[C]" then return false end
return true
end

local function @@H25@@() -- Global table integrity
local env=type(getgenv)=="function" and getgenv() or getfenv(0)
-- Check that critical globals haven't been replaced
if type(env.math)~="table" then return false end
if type(env.string)~="table" then return false end
if type(env.table)~="table" then return false end
if type(env.coroutine)~="table" then return false end
if type(env.os)~="table" then return false end
if type(env.debug)~="table" then return false end
if type(env.package)~="table" then return false end
-- Check math constants
if math.pi<3.14 or math.pi>3.15 then return false end
if type(math.huge)~="number" then return false end
return true
end


-- ============================================================
-- ADVANCED ANTI-TAMPER CHECKS (H26-H40)
-- Based on leaked anti-tamper patterns
-- ============================================================

local function @@H26@@() -- EncodingService Zstd compression/decompression
if type(EncodingService) ~= "table" then return true end
local enc = EncodingService
if type(enc.CompressBuffer) ~= "function" then return false end
if type(enc.DecompressBuffer) ~= "function" then return false end
local test_data = "PSI_TEST_DATA_12345"
local buf = buffer.create(#test_data)
buffer.writestring(buf, 0, test_data)
local ok, compressed = pcall(enc.CompressBuffer, buf, Enum.CompressionAlgorithm.Zstd, 3)
if not ok or type(compressed) ~= "string" or #compressed == 0 then return false end
local ok2, decompressed = pcall(enc.DecompressBuffer, compressed, Enum.CompressionAlgorithm.Zstd)
if not ok2 or type(decompressed) ~= "string" or decompressed ~= test_data then return false end
return true
end

local function @@H27@@() -- bit32 operations completeness
if type(bit32) ~= "table" then return true end
local bit32_ops = {"band", "bor", "bxor", "bnot", "lshift", "rshift", "arshift", "lrotate", "rrotate", "byteswap", "countlz", "countrz", "btest", "extract", "replace"}
for _, name in ipairs(bit32_ops) do
if type(bit32[name]) ~= "function" then return false end
end
if bit32.band(0xFF, 0x0F) ~= 0x0F then return false end
if bit32.bor(0x0F, 0xF0) ~= 0xFF then return false end
if bit32.bxor(0xFF, 0x00) ~= 0xFF then return false end
if bit32.lshift(1, 4) ~= 16 then return false end
if bit32.rshift(16, 2) ~= 4 then return false end
if bit32.arshift(-16, 2) ~= -4 then return false end
if bit32.bnot(0x0F) ~= 0xFFFFFFF0 then return false end
return true
end

local function @@H28@@() -- buffer operations completeness
if type(buffer) ~= "table" then return true end
local buf_names = {"create", "fromstring", "tostring", "len", "readu8", "readu16",
"readi16", "readi32", "readu32", "readf32", "readf64", "readstring",
"writeu8", "writeu16", "writei16", "writei32", "writeu32", "writef32",
"writef64", "writestring", "fill", "copy"}
for _, name in ipairs(buf_names) do
if type(buffer[name]) ~= "function" then return false end
end
local buf = buffer.create(40)
buffer.writeu8(buf, 0, 0xFE)
buffer.writeu16(buf, 1, 0xBEEF)
buffer.writei16(buf, 3, -1234)
buffer.writei32(buf, 5, -123456789)
buffer.writeu32(buf, 9, 0x89ABCDEF)
buffer.writef32(buf, 13, 1.5)
buffer.writef64(buf, 17, math.pi)
buffer.writestring(buf, 25, "PSI}")
if buffer.len(buf) ~= 40 then return false end
if buffer.readu8(buf, 0) ~= 0xFE then return false end
if buffer.readu16(buf, 1) ~= 0xBEEF then return false end
if buffer.readi16(buf, 3) ~= -1234 then return false end
if buffer.readi32(buf, 5) ~= -123456789 then return false end
if buffer.readu32(buf, 9) ~= 0x89ABCDEF then return false end
if math.abs(buffer.readf32(buf, 13) - 1.5) > 0.0001 then return false end
if math.abs(buffer.readf64(buf, 17) - math.pi) > 0.0000001 then return false end
if buffer.readstring(buf, 25, 4) ~= "PSI}" then return false end
return true
end

local function @@H29@@() -- Random deterministic behavior
if type(Random) ~= "function" then return true end
local r1 = Random.new(1515359100)
local expected = {763, 0.52705833430898807, 0.44671507908619318, 397, 847, 0.61786750792918488, 788, 81, 0.37417195152223198, 1008}
local actual = {
r1:NextInteger(532, 1117), r1:NextNumber(), r1:NextNumber(), r1:NextInteger(299, 786),
r1:NextInteger(784, 1062), r1:NextNumber(), r1:NextInteger(695, 1094),
r1:NextInteger(30, 107), r1:NextNumber(), r1:NextInteger(999, 1013)
}
for i = 1, #expected do if actual[i] ~= expected[i] then return false end end
local clone = r1:Clone()
if clone:NextInteger(-1000000, 1000000) ~= r1:NextInteger(-1000000, 1000000) then return false end
if clone:NextNumber() ~= r1:NextNumber() then return false end
return true
end

local function @@H30@@() -- SharedTable checks
if type(SharedTable) ~= "table" then return true end
local t = SharedTable.new({v = 7})
local x = SharedTable.new({n = t, a = 10})
local s = SharedTable.clone(x)
local d = SharedTable.clone(x, true)
s.n.v = 91
local old = SharedTable.increment(x, "a", 5)
local f = SharedTable.cloneAndFreeze(x, true)
if x.n.v ~= 91 then return false end
if d.n.v ~= 7 then return false end
if old ~= 10 then return false end
if x.a ~= 15 then return false end
if not SharedTable.isFrozen(f) then return false end
if not SharedTable.isFrozen(f.n) then return false end
return true
end

local function @@H31@@() -- crypt library with base64
if type(crypt) ~= "table" then return true end
if type(crypt.base64) ~= "table" then return false end
if type(crypt.base64.encode) ~= "function" then return false end
if type(crypt.base64.decode) ~= "function" then return false end
if type(crypt.base64_encode) ~= "function" then return false end
if type(crypt.base64_decode) ~= "function" then return false end
if type(crypt.encrypt) ~= "function" then return false end
if type(crypt.decrypt) ~= "function" then return false end
if type(crypt.generatekey) ~= "function" then return false end
if type(crypt.generatebytes) ~= "function" then return false end
if type(crypt.hash) ~= "function" then return false end
local test = "PSI_TEST"
local encoded = crypt.base64.encode(test)
if type(encoded) ~= "string" or #encoded == 0 then return false end
local decoded = crypt.base64.decode(encoded)
if decoded ~= test then return false end
return true
end

local function @@H32@@() -- Drawing library with getrenderproperty/setrenderproperty/isrenderobj
local ok, draw = pcall(function() return Drawing and Drawing.new end)
if not ok or type(draw) ~= "function" then return true end
local square = draw("Square")
if not square then return false end
pcall(function() square.Visible = true end)
pcall(function() square.Size = Vector2.new(40, 25) end)
local sz = pcall(function() return getrenderproperty(square, "Size") end)
local vis = pcall(function() return getrenderproperty(square, "Visible") end)
local live = pcall(function() return isrenderobj(square) and square.__OBJECT_EXISTS == true end)
pcall(function() square:Destroy() end)
if not (sz and vis and live) then return false end
return true
end

local function @@H33@@() -- EncodingService with Zstd
if type(EncodingService) ~= "table" then return true end
local enc = EncodingService
if type(enc.CompressBuffer) ~= "function" then return false end
if type(enc.DecompressBuffer) ~= "function" then return false end
local test_data = "PSI_TEST_DATA_12345"
local buf = buffer.create(#test_data)
buffer.writestring(buf, 0, test_data)
local ok, compressed = pcall(enc.CompressBuffer, buf, Enum.CompressionAlgorithm.Zstd, 3)
if not ok or type(compressed) ~= "string" or #compressed == 0 then return false end
local ok2, decompressed = pcall(enc.DecompressBuffer, compressed, Enum.CompressionAlgorithm.Zstd)
if not ok2 or type(decompressed) ~= "string" or decompressed ~= test_data then return false end
return true
end

local function @@H34@@() -- bit32 bxor/band/bnot from leaked code
if type(bit32) ~= "table" then return true end
local x = bit32.bxor(0xFF, 0x0F)
if x ~= 0xF0 then return false end
local y = bit32.band(0xFF, 0x0F)
if y ~= 0x0F then return false end
local z = bit32.bnot(0x0F)
if z ~= 0xFFFFFFF0 then return false end
return true
end

local function @@H35@@() -- string.byte/string.sub from leaked code
local s = "PSI_TEST_12345"
local b1 = string.byte(s, 2, 4)
if type(b1) ~= "number" then return false end
local b2 = string.byte(s, 1, 1)
if b2 ~= string.byte("P") then return false end
local sub = string.sub(s, 4, 10)
if sub ~= "TEST_12" then return false end
return true
end

local function @@H36@@() -- buffer.readu32/readi32 from leaked code
if type(buffer) ~= "table" then return true end
local buf = buffer.create(40)
buffer.writeu8(buf, 0, 0xFE)
buffer.writeu16(buf, 1, 0xBEEF)
buffer.writei16(buf, 3, -1234)
buffer.writei32(buf, 5, -123456789)
buffer.writeu32(buf, 9, 0x89ABCDEF)
local u32 = buffer.readu32(buf, 0)
if u32 ~= 0xFE + 0xBEEF * 256 + 0xFFFF * 65536 + 0xFFFF * 16777216 then return false end
local i32 = buffer.readi32(buf, 5)
if i32 ~= -123456789 then return false end
return true
end

local function @@H37@@() -- debug.info checks
local inf = resolve(@@F8@@+16, true)
if type(inf) ~= "function" then return true end
local t = {}
local ok, info = pcall(debug.info, t, "s")
if ok and type(info) == "string" then return false end
local ok2, info2 = pcall(debug.info, print, "s")
if not ok2 or info2 ~= "[C]" then return false end
return true
end

local function @@H38@@() -- Environment time checks
local t1 = os.clock()
local sum = 0
for i = 1, 10000 do sum = sum + i end
local t2 = os.clock()
if t2 <= t1 then return false end
if (t2 - t1) > 1.0 then return false end
local t3 = os.time()
task.wait(1.1)
local t4 = os.time()
if t4 <= t3 then return false end
return true
end

local function @@H39@@() -- bit32.bxor chain from leaked code pattern
if type(bit32) ~= "table" then return true end
local result = 231
local bytes = {0x01, 0x02, 0x03, 0x04}
for i = 1, #bytes do
    result = bit32.bxor(result, bytes[i]) % 256
end
local expected = bit32.bxor(bit32.bxor(bit32.bxor(231, 1), 2), 3) % 256
expected = bit32.bxor(expected, 4) % 256
if result ~= expected then return false end
return true
end

local function @@H40@@() -- String integrity check
local str = "PSI_INTEGRITY_CHECK_" .. tostring(os.clock())
if str:find("%s%s") then return false end
if str:find("
%s*
") then return false end
if #str < 20 then return false end
return true
end

"""


RESERVED = set("""
P DATA NP CH ENV SYM START raw PB PROTOS SOFF SLEN2 CANI CANV NCAN2 NPROTO
NSTR pos rdint dec uncomp rdu32 mkstr K SCACHE RCACHE resolve UP TP call
docall MAIN run b64dec GUARD GUARDIDX WOFF self op a b c d pr code nregs
nparams R U V RES pc from len to by ok nv name idx sd byte q acc bits out
x y z e f g m o q r w t h s i j n l k v ar res cn nb f st
and break do else elseif end false for function if in local nil not or repeat
return then true until while continue export type global
O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
""".split())


# ============================================================
# the names the vm needs are appended to the constant table and travel
# encrypted with the program - the payload itself never spells them out
def _rand_name(rng, used):
    """A short, meaningless identifier (looks like normal code).

    Uses a mix of lowercase, uppercase, digits and underscores so generated
    names are harder to recognise as machine generated.
    """
    alphabet = ("abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789_")
    first = rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
    while True:
        n = rng.choice((2, 2, 3, 3, 3, 4, 4, 5))
        name = first + "".join(rng.choice(alphabet) for _ in range(n - 1))
        if name in used or name in RESERVED or name.startswith("__"):
            continue
        if name.strip("_") == "":
            continue
        used.add(name)
        return name


def obfuscate_names(vm, rng):
    """Replace the guard identifiers with per build random names."""
    used = set()
    # never shadow an identifier the vm already uses
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", vm):
        used.add(ident)
    tokens = ["@@H1@@", "@@H2@@", "@@H3@@", "@@H4@@", "@@H5@@", "@@H6@@", "@@H7@@",
              "@@H8@@", "@@H9@@", "@@H10@@", "@@H11@@", "@@H12@@", "@@H13@@", "@@H14@@",
              "@@H15@@", "@@H16@@", "@@H17@@", "@@H18@@", "@@H19@@", "@@H20@@",
              "@@H21@@", "@@H22@@", "@@H23@@", "@@H24@@", "@@H25@@",
              "@@H26@@", "@@H27@@", "@@H28@@", "@@H29@@", "@@H30@@",
              "@@H31@@", "@@H32@@", "@@H33@@", "@@H34@@", "@@H35@@",
              "@@H36@@", "@@H37@@", "@@H38@@", "@@H39@@", "@@H40@@",
              "@@V1@@", "@@V2@@"]
    tokens += ["@@F%d@@" % i for i in range(15)]
    tokens += ["@@V%d@@" % i for i in range(3, 9)]
    for token in tokens:
        name = _rand_name(rng, used)
        vm = vm.replace(token, name)
    return vm


def _append_names(program, names):
    """Append raw string constants to the constant table.

    They are *not* deduplicated on purpose: the vm addresses them by a fixed
    offset (LIB0 + n), so every name needs its own slot.  Returns the 1 based
    index of the first appended name.
    """
    base = len(program.strings) + 1
    for name in names:
        program.strings.append("\0" + name)
    return base


def strip_comments(src):
    """Remove lua line comments.

    The vm body is emitted as a single line, so a `--` comment would swallow
    the rest of the vm.  Strings are left alone.
    """
    out = []
    for line in src.split("\n"):
        res = []
        quote = None
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if quote is not None:
                res.append(ch)
                if ch == "\\" and i + 1 < n:
                    res.append(line[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch == '"' or ch == "'":
                quote = ch
                res.append(ch)
                i += 1
                continue
            if ch == "-" and i + 1 < n and line[i + 1] == "-":
                break
            res.append(ch)
            i += 1
        out.append("".join(res))
    return "\n".join(out)


# the outer shape of the protected file - a different one is picked per build
WRAPPERS = [
    'return (function({t},...) return {t}["{k}"]({t},...) end)({tab})',
    'return({tab})',
    'return (function(...) local {t}={tab} return {t}["{k}"]({t},...) end)(...)',
    'return (function({t},...) local {f}={t}["{k}"] return {f}({t},...) end)({tab})',
]


# the bodies of the fake (decoy) vm levels - never executed, but they carry
# the same kind of integrity probing as a real vm level so that any static
# analysis that looks for a real vm finds a convincing decoy
FAKE_VM_TMPL = (
    "local D = self[{FD}] if type(D) ~= 'string' then return end "
    "local E = (getfenv and getfenv(1)) or _G if type(E) ~= 'table' then return end "
    "local MT = getmetatable(E) if type(MT) == 'table' then "
    "if type(MT.__index) == 'function' then return end "
    "if type(MT.__newindex) == 'function' then return end end "
    "for K in pairs(E) do "
    "if type(K) == 'string' and K:sub(1, 2) == '__' then "
    "if type(E[K]) == 'function' then return end end end "
    "local T0 = os.clock() local S = 0 "
    "for I = 1, 100 do S = S + I end "
    "if (os.clock() - T0) > 0.05 then return end "
    "local INF = (debug and debug.info) "
    "if type(INF) == 'function' then "
    "local OK, SI = pcall(INF, INF, 's') "
    "if OK and type(SI) == 'string' and SI ~= '[C]' and SI ~= '' then return end end "
    "return 42"
)


def build_guard_block(rng):
    """The periodic integrity check - the order of the checks is randomised."""
    checks = [
        "if not @@H7@@() then @@H2@@() end",
        "if not @@H3@@() then @@H2@@() end",
        "if not @@H5@@() then @@H2@@() end",
        "if not @@H8@@(GUARDIDX%@@F6@@+1) then @@H2@@() end",
        "if not @@H10@@() then @@H2@@() end",
        "if not @@H11@@() then @@H2@@() end",
        "if not @@H12@@() then @@H2@@() end",
        "if not @@H13@@() then @@H2@@() end",
        "if not @@H14@@() then @@H2@@() end",
        "if not @@H15@@() then @@H2@@() end",
        "if not @@H16@@() then @@H2@@() end",
        "if not @@H17@@() then @@H2@@() end",
        "if not @@H18@@() then @@H2@@() end",
        "if not @@H19@@() then @@H2@@() end",
        "if not @@H20@@() then @@H2@@() end",
        "if not @@H21@@() then @@H2@@() end",
        "if not @@H22@@() then @@H2@@() end",
        "if not @@H23@@() then @@H2@@() end",
        "if not @@H24@@() then @@H2@@() end",
        "if not @@H25@@() then @@H2@@() end",
        "if not @@H26@@() then @@H2@@() end",
        "if not @@H27@@() then @@H2@@() end",
        "if not @@H28@@() then @@H2@@() end",
        "if not @@H29@@() then @@H2@@() end",
        "if not @@H30@@() then @@H2@@() end",
        "if not @@H31@@() then @@H2@@() end",
        "if not @@H31@@() then @@H2@@() end",
        "if not @@H32@@() then @@H2@@() end",
        "if not @@H33@@() then @@H2@@() end",
        "if not @@H34@@() then @@H2@@() end",
        "if not @@H35@@() then @@H2@@() end",
        "if not @@H36@@() then @@H2@@() end",
        "if not @@H37@@() then @@H2@@() end",
        "if not @@H38@@() then @@H2@@() end",
        "if not @@H39@@() then @@H2@@() end",
        "if not @@H40@@() then @@H2@@() end",
    ]
    rng.shuffle(checks)
    every = rng.choice((1024, 2048, 4096, 4096, 8192, 16384))
    return ("if GUARD>=%d then\nGUARD=0\n%s\nGUARDIDX=GUARDIDX+1\nend"
            % (every, "\n".join(checks)))

def build_header(meta):
    """The header reads - the field order changes with every build."""
    t = FIELD_TOKENS
    lines = []
    for name, off in meta["layout"]:
        # the layout offsets are 0 based, the vm indexes 1 based
        lines.append("local %s=rdu32(raw,%d)" % (t[name], off + 1))
    lines.append("local %s={}" % t["WHASH"])
    lines.append("for i=1,%s do %s[i]=rdu32(raw,%d+4*(i-1)) end"
                 % (t["NWIN"], t["WHASH"], meta["win_base"] + 1))
    lines.append("local %s=%d+4*%s" % (t["PROGBASE"], meta["win_base"] + 1,
                                       t["NWIN"]))
    return "\n".join(lines)


def build_dec(variant):
    """The stream cipher - the lcg and the combiner change per build."""
    mul, mod, mask = E.LCG_SETS[variant["ks"] % len(E.LCG_SETS)]
    comb = variant["comb"] % 3
    if comb == 0:
        expr = "(t[i]-y%256)%256"
    elif comb == 1:
        expr = "(t[i]+y%256)%256"
    else:
        expr = "(t[i]-y%256*3)%256"
    return (
        "local function dec(t,off,len,sd)\n"
        "local out={}\n"
        "local x=sd%%%d\n"
        "if x==0 then x=1 end\n"
        "for i=off,off+len-1 do\n"
        "x=(x*%d)%%%d\n"
        "local y=x-x%%%d\n"
        "out[#out+1]=%s\n"
        "end\n"
        "return out\n"
        "end" % (mod, mul, mod, mask, expr)
    )


def build_hash(variant):
    """The integrity hash - the constants change per build."""
    h0, mul, scale = E.HASH_SETS[variant["hash"] % len(E.HASH_SETS)]
    return (
        "local function @@H1@@(t,from,len)\n"
        "local h=%d\n"
        "if not from then from=1 end\n"
        "if not len then len=#t end\n"
        "for i=from,from+len-1 do\n"
        "h=(h*%d+((t[i] or 0)*%d))%%4294967296\n"
        "end\n"
        "return h\n"
        "end" % (h0, mul, scale)
    )


def build_payload(program, options):
    rng = options.get("rng") or random.Random()
    opmap = options.get("opmap") or make_opmap(rng)
    opcount = len(opmap)
    seed = rng.randrange(1, 0x7FFFFFFF)
    alphabet = E.make_alphabet(rng)
    # every build uses a different set of primitives and a different layout
    variant = {
        "ks": rng.randrange(0, len(E.LCG_SETS)),
        "comb": rng.randrange(0, 3),
        "hash": rng.randrange(0, len(E.HASH_SETS)),
        "ss": rng.randrange(0, len(E.STRING_SEED_MULS)),
        "op": rng.randrange(0, 2),
    }
    field_order = list(range(11))
    rng.shuffle(field_order)
    operand_order = list(options.get("operand_order") or (0, 1, 2, 3))
    # every vm level gets its own opcode key -> the dispatch tables of the
    # outer loader and the inner program never look the same
    key_inner = rng.randrange(1, 256)
    key_outer = rng.randrange(1, 256)
    if variant["op"] % 2 == 1:
        # the multiplicative key needs an odd value (it has an inverse)
        key_inner |= 1
        key_outer |= 1
    for p in program.protos:
        p.key = key_outer if getattr(p, "loader", False) else key_inner
    sled = int(options.get("sled") or 0)
    if sled > 0 and program.protos:
        # the nop sled lives behind the code of the main proto: our vm never
        # reaches it, but any tool that copies/dumps the instruction array
        # has to walk 100 million entries first
        program.protos[0].sled = sled

    # the names the vm needs are appended to the constant table and travel
    # encrypted with the program - the payload itself never spells them out
    lib0 = _append_names(program, VM_NAMES)
    prb0 = _append_names(program, PROBE_NAMES)
    mtb0 = _append_names(program, META_NAMES)

    # the number of integrity windows / canaries changes per build
    windows = rng.randrange(8, 25)
    canary_count = rng.randrange(8, 25)

    marker = bytes(rng.randrange(0, 256) for _ in range(4))
    blob, meta = E.build_blob(program, seed,
                              compress_data=not options.get("no_compress"),
                              marker=marker, lib0=lib0, prb0=prb0, mtb0=mtb0,
                              windows=windows, canary_count=canary_count,
                              variant=variant, field_order=field_order)
    if os.environ.get("PSI_DUMP_BLOB"):
        print("variant:", variant)
        print("layout:", meta["layout"])
        print("win_base:", meta["win_base"], "prog_base:", meta["prog_base"],
              "bloblen:", len(blob))
    blob_text = E.b64_encode(blob, alphabet)

    dispatch = build_dispatch(opmap, indent="\t")
    vm = VM_BODY.replace("__DISPATCH__", dispatch)
    vm = vm.replace("__HEADER__", build_header(meta))
    vm = vm.replace("__DEC__", build_dec(variant))
    vm = vm.replace("__STRSEED__", "(%s+(i-1)*%d)%%4294967296"
                    % (FIELD_TOKENS["SEED"],
                       E.STRING_SEED_MULS[variant["ss"] % len(E.STRING_SEED_MULS)]))
    vm = vm.replace("__OPKEY__", "(code[i]*kk)%256" if variant["op"] % 2 == 1
                    else "(code[i]-kk)%256")
    vm = vm.replace("@@OPMAX@@", str(opcount))
    vm = vm.replace("__SA__", str(operand_order.index(0) + 1))
    vm = vm.replace("__SB__", str(operand_order.index(1) + 1))
    vm = vm.replace("__SC__", str(operand_order.index(2) + 1))
    vm = vm.replace("__SD__", str(operand_order.index(3) + 1))
    if not options.get("no_trap"):
        vm = vm.replace("call=function(pi,args,upvals)",
                        TRAP + "\ncall=function(pi,args,upvals)")
        vm = vm.replace("__GUARDBLOCK__", build_guard_block(rng))
        vm = vm.replace("__HASH__", build_hash(variant))
        vm = vm.replace("__OPFAIL__", "@@H2@@()")
    else:
        vm = vm.replace("__GUARDBLOCK__", "")
        vm = vm.replace("if op<1 or op>%d then __OPFAIL__ end\n" % opcount, "")
    vm = vm.replace("@@PRBN@@", "81")
    vm = vm.replace("@@MTBN@@", str(len(META_NAMES)))
    vm = vm.replace("@@NOP@@", str(opmap[C.OP_JUNK]))
    if os.environ.get("PSI_DEBUG_TRAP"):
        vm = re.sub(r"if not ([A-Za-z_@][A-Za-z0-9_@]*)\(\) then ([A-Za-z_@][A-Za-z0-9_@]*)\(\) end",
                    r"if not \1() then print('FAILCHECK \1') \2() end", vm)
    vm = vm.replace("@@DEBUG_TRAP@@",
                    "true" if os.environ.get("PSI_DEBUG_TRAP") else "false")
    vm = obfuscate_names(vm, rng)
    if os.environ.get("PSI_DUMP_VM"):
        with open(os.environ["PSI_DUMP_VM"], "w", encoding="utf-8") as fh:
            fh.write(vm)

    # the payload keys are random per build, so the shape of the file differs
    used = set()
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", vm):
        used.add(ident)
    key_data = _rand_name(rng, used)
    key_vm = _rand_name(rng, used)
    var = _rand_name(rng, used)
    fn = _rand_name(rng, used)
    vm = vm.replace("@@KB@@", '"%s"' % key_data)

    # the protected file has exactly two fields: the opaque data stream
    # (alphabet + encrypted program + padding) and the vm itself
    vm_field = '["%s"]=function(self,...)%s end' % (
        key_vm, strip_comments(vm).replace("\n", " "))
    wrapper = rng.choice(WRAPPERS)

    def make_body(data):
        lit = long_bracket(data.encode("utf-8")).decode("utf-8")
        fields = [vm_field, '["%s"]=%s' % (key_data, lit)]
        # five fake (decoy) vm levels - never executed, but they look like real
        # vms with their own integrity probing so static analysers get lost
        for _fi in range(5):
            _fk = _rand_name(rng, used)
            _fd = _rand_name(rng, used)
            _fb = FAKE_VM_TMPL.replace("{FD}", _fd)
            fields.append('["%s"]=function(self, ...) %s end' % (_fk, _fb))
        body = wrapper.format(t=var, f=fn, k=key_vm,
                              tab="{%s}" % ",".join(fields))
        return minify_lua(body)

    data_text = alphabet + blob_text

    # keep the payload inside the wanted size window: pad it with filler the
    # vm never reads (a protected file should not look "small")
    ms = options.get("min_size")
    xs = options.get("max_size")
    min_size = MIN_PAYLOAD_SIZE if ms is None else int(ms)
    max_size = MAX_PAYLOAD_SIZE if xs is None else int(xs)
    out_line = make_body(data_text)
    size = len(out_line.encode("utf-8"))
    pad = min_size - size
    room = max_size - size
    if pad > 0 and room > 0:
        pad = min(pad, room)
        # the filler is made of symbols as well, so the whole file is unicode
        # soup (sized in bytes, not in characters)
        chunks = []
        nbytes = 0
        while nbytes < pad:
            ch = rng.choice(alphabet)
            clen = len(ch.encode("utf-8"))
            if nbytes + clen > pad:
                break
            chunks.append(ch)
            nbytes += clen
        out_line = make_body(data_text + "".join(chunks))

    parts = []
    parts.append(HEADER)
    parts.append("")
    parts.append(out_line)
    return "\n".join(parts)
