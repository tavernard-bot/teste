# -*- coding: utf-8 -*-
"""
IDA falso (so para teste de fumaca de analisar_ida.py fora do IDA).
Simula um binario x64 minimo com 8 funcoes, uma tabela de doubles e um import.
Nao substitui testar no IDA real.
"""
import struct
import sys
import types

BAD = 0xFFFFFFFFFFFFFFFF
BASE = 0x180000000

# ---- binario de brinquedo ---------------------------------------------------
TEXT, RDATA, DATA, IDATA = 0x180001000, 0x180003000, 0x180004000, 0x180003800
MEM = {}      # ea -> byte
NAMES = {}
FUNCS = {}    # ea -> dict(end, flags, items)
XR = {}       # frm -> [(to, type)]
XRTO = {}
IAT = {IDATA: ("libifcoremd.dll", "for_write_seq_lis", 0)}
SEGS = []
FL_LIB, FL_THUNK, FL_NORET = 0x4, 0x80, 0x1

FL_CN, FL_CF, FL_JN, FL_JF, FL_F = 17, 16, 19, 18, 21
DR_O, DR_W, DR_R = 1, 2, 3


def _w(ea, data):
    for i, b in enumerate(data):
        MEM[ea + i] = b


def _func(ea, nome, n_ins, flags=0, mnems=None):
    items = [ea + 4 * k for k in range(n_ins)]
    FUNCS[ea] = {"end": ea + 4 * n_ins, "flags": flags, "items": items,
                 "mn": mnems or ["mov"] * n_ins}
    NAMES[ea] = nome


def _xref(frm, to, tp):
    XR.setdefault(frm, []).append((to, tp))
    XRTO.setdefault(to, []).append((frm, tp))


def _init():
    SEGS.extend([("..text", TEXT, TEXT + 0x1000, 5, 2), (".rdata", RDATA, RDATA + 0x100, 4, 3),
                 (".data", DATA, DATA + 0x100, 6, 3), (".idata", IDATA, IDATA + 8, 4, 3)])
    # tabela de 8 doubles (coeficientes) + 1 double isolado
    for k, v in enumerate([1.5, -2.25, 3.125e-3, 4.0e2, 5.5, 6.75, -7.125, 8.0625]):
        _w(RDATA + 8 * k, struct.pack("<d", v))
    _w(RDATA + 0x80, struct.pack("<d", 273.15))
    NAMES[RDATA] = "COEF_TAB"
    NAMES[RDATA + 0x80] = "T0"
    _w(RDATA + 0xA0, b"Erro de dominio\x00")
    # funcoes
    _func(TEXT + 0x000, "MOD_mp_LEAF_", 6, mnems=["movsd", "mulsd", "addsd", "ret", "vfmadd231sd", "fld"])
    _func(TEXT + 0x100, "MOD_mp_TOP_", 5, mnems=["call", "call", "call", "lea", "ret"])
    _func(TEXT + 0x200, "ping", 3)
    _func(TEXT + 0x280, "pong", 3)
    _func(TEXT + 0x300, "__security_check_cookie", 2)
    _func(TEXT + 0x400, "memcpy", 2, flags=FL_LIB)
    _func(TEXT + 0x500, "?Calc@Foo@@QEAAHH@Z", 4, mnems=["movsd", "call", "mov", "ret"])
    _func(TEXT + 0x600, "_DllMainCRTStartup", 3)
    _func(TEXT + 0x700, "j_thunk", 1, flags=FL_THUNK)
    # xrefs
    _xref(TEXT + 0x000, RDATA, DR_R)                 # LEAF le a tabela
    _xref(TEXT + 0x004, RDATA + 0x80, DR_R)
    _xref(TEXT + 0x100, TEXT + 0x000, FL_CN)         # TOP -> LEAF
    _xref(TEXT + 0x104, IDATA, DR_R)                 # TOP -> import
    _xref(TEXT + 0x108, TEXT + 0x200, FL_CN)         # TOP -> ping
    _xref(TEXT + 0x10C, RDATA + 0xA0, DR_O)          # string
    _xref(TEXT + 0x200, TEXT + 0x280, FL_CN)         # ping <-> pong (ciclo)
    _xref(TEXT + 0x280, TEXT + 0x200, FL_CN)
    _xref(TEXT + 0x500, RDATA + 0x80, DR_R)          # Calc le T0 (double 273.15)
    _xref(TEXT + 0x504, TEXT + 0x000, FL_CN)         # Calc -> LEAF
    _xref(TEXT + 0x110, TEXT + 0x500, FL_CN)         # TOP -> Calc
    _xref(TEXT + 0x600, TEXT + 0x300, FL_CN)         # entry -> cookie
    _xref(TEXT + 0x604, TEXT + 0x500, FL_CN)         # entry -> metodo (DllMain)


_init()


def _seg_of(ea):
    for s in SEGS:
        if s[1] <= ea < s[2]:
            return s
    return None


# ---- modulos ----------------------------------------------------------------
def _mod(nome, **attrs):
    m = types.ModuleType(nome)
    m.__dict__.update(attrs)
    sys.modules[nome] = m
    return m


class _Seg:
    def __init__(self, t):
        self.name, self.start_ea, self.end_ea, self.perm, self.type = t


class _Func:
    def __init__(self, ea):
        self.start_ea, self.end_ea, self.flags = ea, FUNCS[ea]["end"], FUNCS[ea]["flags"]


def _get_func(ea):
    for s, d in FUNCS.items():
        if s <= ea < d["end"]:
            return _Func(s)
    return None


class _Xr:
    def __init__(self, frm, to, tp):
        self.frm, self.to, self.type = frm, to, tp


class _Str:
    def __init__(self, ea, txt):
        self.ea, self.txt, self.length = ea, txt, len(txt)

    def __str__(self):
        return self.txt


class DecompilationFailure(Exception):
    errea = BASE + 0x1234


class _CFunc:
    def __init__(self, ea):
        self.ea = ea

    def __str__(self):
        n = NAMES[self.ea]
        chamadas = "".join(f"  {NAMES[t]}(a1, a2);\n" for it in FUNCS[self.ea]["items"]
                           for t, tp in XR.get(it, []) if tp == FL_CN and t in NAMES)
        return f"__int64 __fastcall {n}(double *a1, int *a2)\n{{\n{chamadas}  return 0;\n}}"

    def get_func_type(self, tif):
        tif._decl = f"__int64 __fastcall {NAMES[self.ea]}(double *a1, int *a2)"
        return True


class _Tif:
    _decl = None

    def _print(self, nome, flags=0):
        return self._decl or ""

    def get_func_details(self, ftd):
        ftd.cc = 0x40
        ftd.rettype = "__int64"
        ftd._a = [("double *", "a1"), ("int *", "a2")]
        return True

    def __str__(self):
        return self._decl or ""

    def get_numbered_type(self, til, k):
        return False


class _Ftd:
    cc = 0
    rettype = ""

    def size(self):
        return len(self._a)

    def __getitem__(self, k):
        t, n = self._a[k]
        return types.SimpleNamespace(type=t, name=n)


REANALISADAS = set()


def decompile(ea):
    if ea == TEXT + 0x500:
        raise DecompilationFailure("call analysis failed")
    if ea == TEXT + 0x280 and ea not in REANALISADAS:
        raise DecompilationFailure("positive sp value has been found")
    return _CFunc(ea)


def install():
    _mod("ida_auto", auto_wait=lambda: True)
    _mod("ida_bytes",
         get_byte=lambda ea: MEM.get(ea, 0),
         get_bytes=lambda ea, n: bytes(MEM.get(ea + i, 0) for i in range(n)),
         get_dword=lambda ea: struct.unpack("<I", bytes(MEM.get(ea + i, 0) for i in range(4)))[0],
         get_qword=lambda ea: struct.unpack("<Q", bytes(MEM.get(ea + i, 0) for i in range(8)))[0],
         get_flags=lambda ea: ("str" if ea == RDATA + 0xA0 else "dbl" if RDATA <= ea < RDATA + 0x40 or ea == RDATA + 0x80
                               else "code" if _seg_of(ea) and _seg_of(ea)[3] & 1 else "data"),
         get_item_size=lambda ea: 16 if ea == RDATA + 0xA0 else 8 if (RDATA <= ea < RDATA + 0x100) else 8,
         is_byte=lambda f: False, is_word=lambda f: False, is_dword=lambda f: False,
         is_qword=lambda f: f == "data", is_float=lambda f: False, is_double=lambda f: f == "dbl",
         is_strlit=lambda f: f == "str", is_code=lambda f: f == "code", is_data=lambda f: f in ("dbl", "data", "str"),
         is_tail=lambda f: False,
         next_head=lambda ea, fim: ea + (16 if ea == RDATA + 0xA0 else 8) if ea + 8 < fim else BAD)
    ents = [(1, TEXT + 0x000, "MOD_mp_LEAF_"), (2, TEXT + 0x100, "MOD_mp_TOP_"),
            (3, TEXT + 0x500, "?Calc@Foo@@QEAAHH@Z"), (TEXT + 0x600, TEXT + 0x600, "_DllMainCRTStartup")]
    _mod("ida_entry", get_entry_qty=lambda: len(ents), get_entry_ordinal=lambda i: ents[i][0],
         get_entry=lambda o: [e for e in ents if e[0] == o][0][1],
         get_entry_name=lambda o: [e for e in ents if e[0] == o][0][2],
         get_entry_forwarder=lambda o: "")
    _mod("ida_funcs", FUNC_LIB=FL_LIB, FUNC_THUNK=FL_THUNK, FUNC_NORET=FL_NORET,
         get_func=_get_func, get_func_name=lambda ea: NAMES.get(ea, ""),
         reanalyze_function=lambda f: REANALISADAS.add(f.start_ea))
    _mod("ida_gdl", FlowChart=_flowchart)
    _mod("ida_ida", inf_is_64bit=lambda: True, inf_get_start_ip=lambda: TEXT + 0x600,
         inf_get_cc_id=lambda: 1, inf_get_procname=lambda: "metapc")
    _mod("ida_lines", tag_remove=lambda s: s,
         generate_disasm_line=lambda ea, f: f"{_mnem(ea)} rax, rbx")
    _mod("ida_name", MNG_SHORT_FORM=1, MNG_LONG_FORM=2, SN_FORCE=1, SN_NOCHECK=2, SN_NOWARN=4,
         demangle_name=lambda n, f: "Foo::Calc(int)" if n.startswith("?Calc") else None,
         get_name=lambda ea: NAMES.get(ea, ""), set_name=_set_name)
    _mod("ida_nalt", get_import_module_qty=lambda: 1, get_import_module_name=lambda i: "libifcoremd.dll",
         enum_import_names=lambda i, cb: [cb(ea, n, o) for ea, (d, n, o) in IAT.items()] and None,
         get_input_file_path=lambda: "/tmp/x/mock.dll", get_root_filename=lambda: "mock.dll",
         get_imagebase=lambda: BASE, get_tinfo=lambda tif, ea: False,
         retrieve_input_file_sha256=lambda: b"\x01" * 32)
    _mod("ida_pro", qexit=lambda rc: setattr(sys.modules["ida_pro"], "rc", rc))
    _mod("ida_segment", SEGPERM_EXEC=1, SEGPERM_WRITE=2, SEG_BSS=9, SEG_XTRN=5,
         get_segm_qty=lambda: len(SEGS), getnseg=lambda i: _Seg(SEGS[i]),
         get_segm_name=lambda s: s.name, getseg=lambda ea: (lambda t: _Seg(t) if t else None)(_seg_of(ea)))
    _mod("ida_typeinf", CM_CC_MASK=0xF0, CM_CC_FASTCALL=0x40, CM_CC_CDECL=0x10, PRTYPE_1LINE=1,
         PRTYPE_DEF=2, PRTYPE_MULTI=4, PRTYPE_SEMI=8, PRTYPE_TYPE=16, tinfo_t=_Tif, func_type_data_t=_Ftd,
         get_idati=lambda: None, get_ordinal_limit=lambda t: 3, get_ordinal_count=lambda t: 2,
         get_compiler_name=lambda i: "Visual C++")
    _mod("ida_xref", fl_CN=FL_CN, fl_CF=FL_CF, fl_JN=FL_JN, fl_JF=FL_JF, dr_O=DR_O, dr_R=DR_R, dr_W=DR_W)
    _mod("idaapi", BADADDR=BAD)
    _mod("idautils",
         Functions=lambda: sorted(FUNCS),
         FuncItems=lambda ea: iter(FUNCS[ea]["items"]),
         Names=lambda: iter(sorted(NAMES.items())),
         Strings=lambda: [_Str(RDATA + 0xA0, "Erro de dominio")],
         XrefsFrom=lambda ea, fl=0: [_Xr(ea, t, tp) for t, tp in XR.get(ea, [])],
         XrefsTo=lambda ea, fl=0: [_Xr(f, ea, tp) for f, tp in XRTO.get(ea, [])])
    _mod("idc", OFILE_ASM=1, o_reg=1, o_phrase=3, o_displ=4,
         gen_file=lambda t, p, a, b, f: open(p, "w").write("; asm completo\n") is not None,
         get_operand_type=lambda ea, n: 7, get_strlit_contents=lambda ea: b"Erro de dominio",
         get_type=lambda ea: None, guess_type=lambda ea: None, print_insn_mnem=lambda ea: _mnem(ea))
    _mod("ida_hexrays", init_hexrays_plugin=lambda: True, decompile=decompile,
         DecompilationFailure=DecompilationFailure)


class _BB:
    def __init__(self, a, b, preds, succs):
        self.start_ea, self.end_ea, self._p, self._s = a, b, preds, succs

    def preds(self):
        return iter(self._p)

    def succs(self):
        return iter(self._s)


class _FC(list):
    size = 2


def _flowchart(f):
    meio = f.start_ea + 8 if f.end_ea - f.start_ea >= 12 else f.end_ea
    b1 = _BB(f.start_ea, meio, [], [])
    if meio == f.end_ea:
        return _FC([b1])
    b2 = _BB(meio, f.end_ea, [b1], [])
    b1._s = [b2]
    return _FC([b1, b2])


def _mnem(ea):
    fn = _get_func(ea)
    if not fn:
        return "nop"
    d = FUNCS[fn.start_ea]
    return d["mn"][d["items"].index(ea)] if ea in d["items"] else "nop"


def _set_name(ea, nome, flags=0):
    NAMES[ea] = nome
    return True
