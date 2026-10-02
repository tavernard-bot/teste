# -*- coding: utf-8 -*-
"""
analisar_ida.py - roda DENTRO do IDA Pro 9.1 (ida -A -S"analisar_ida.py" dll).

Variaveis de ambiente lidas (todas opcionais, definidas pelo orquestrar.py):
  IDA_OUTPUT          pasta de saida (padrao: pasta da DLL)
  RECOVERY_SCRIPTS    pasta onde esta analise_comum.py
  IDA_SOFT_DEADLINE   epoch (segundos) apos o qual a decompilacao para e o que ja
                      existe e fechado de forma limpa (evita matar o IDA no meio)
  IDA_DECOMPILE_LIB   1 = tambem decompila funcoes de biblioteca (pasta lib\\)
  IDA_ASM_FULL        1 (padrao) = gera disasm_completo.asm do banco inteiro
  IDA_RENOMEAR        1 (padrao) = renomeia simbolos com caracteres invalidos em C
  IDA_MAX_DATA_ITEMS  limite de itens de dados varridos (padrao 600000)

Saidas (tudo em IDA_OUTPUT):
  functions.txt functions.json segments.txt imports_ida.txt exports_ida.txt strings.txt
  exports_prototypes.json   callgraph.json callgraph_edges.csv ordem_reescrita.csv
  funcoes_biblioteca.txt    renomeacoes.csv
  projeto\\src\\<funcao>.c   projeto\\include\\{funcoes.h,tipos.h}  projeto\\lib\\ (opcional)
  pseudocode_hexrays.c (so codigo do usuario, folhas primeiro)
  decompile_failures.txt/.csv   asm\\<funcao>.asm   disasm_completo.asm
  data\\{data_globals.csv,constantes_float.csv,tabelas_candidatas.csv,tabelas.c,globais.c,*.bin}
  classes_rtti.json classes_skeleton.hpp
  analysis_summary.txt analysis_summary.json
"""
import collections
import os
import re
import sys
import time
import traceback

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_gdl
import ida_ida
import ida_lines
import ida_name
import ida_nalt
import ida_pro
import ida_segment
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc

try:
    _AQUI = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _AQUI = ""
for _p in (os.environ.get("RECOVERY_SCRIPTS"), _AQUI):
    if _p and _p not in sys.path:
        sys.path.insert(0, _p)
import analise_comum as ac  # noqa: E402

# ---------------------------------------------------------------------------
# Configuracao
# ---------------------------------------------------------------------------
INICIO = time.time()
OUT = os.environ.get("IDA_OUTPUT") or os.path.dirname(os.path.abspath(ida_nalt.get_input_file_path()))
OUT = os.path.abspath(OUT)
PROJ = os.path.join(OUT, "projeto")
SRC = os.path.join(PROJ, "src")
INC = os.path.join(PROJ, "include")
LIBDIR = os.path.join(PROJ, "lib")
ASMDIR = os.path.join(OUT, "asm")
DATADIR = os.path.join(OUT, "data")
for _d in (OUT, SRC, INC, ASMDIR, DATADIR):
    os.makedirs(_d, exist_ok=True)


def _env_int(nome, padrao):
    try:
        return int(os.environ.get(nome, padrao))
    except ValueError:
        return padrao


def _env_float(nome, padrao):
    try:
        return float(os.environ.get(nome, padrao))
    except ValueError:
        return padrao


DEADLINE = _env_float("IDA_SOFT_DEADLINE", 0.0)       # epoch; 0 = sem prazo
DECOMPILAR_LIB = _env_int("IDA_DECOMPILE_LIB", 0) == 1
ASM_FULL = _env_int("IDA_ASM_FULL", 1) == 1
RENOMEAR = _env_int("IDA_RENOMEAR", 1) == 1
MAX_DATA_ITEMS = _env_int("IDA_MAX_DATA_ITEMS", 600000)

IS64 = ida_ida.inf_is_64bit()
PTR = 8 if IS64 else 4
BADADDR = idaapi.BADADDR
NOME_DLL = os.path.splitext(ida_nalt.get_root_filename())[0]

STATUS = {"fases": {}, "avisos": []}
F = {}            # ea -> info da funcao
IMPORTS = {}      # ea do slot IAT -> (dll, nome, ordinal)
EXPORTS = []      # lista de dicts
ENTRY_EA = None   # ponto de entrada do PE (DllMain/CRT startup)
ISA = collections.Counter()
FALHAS = {}       # ea -> {motivo, arq, ...} (funcoes de usuario que o Hex-Rays nao decompilou)
ORDEM_ARQ = []


def prazo_estourado():
    return bool(DEADLINE) and time.time() > DEADLINE


def write(nome, texto, base=None):
    with open(os.path.join(base or OUT, nome), "w", encoding="utf-8", errors="replace") as f:
        f.write(texto)


def aviso(msg):
    STATUS["avisos"].append(msg)


def fase(nome, fn, *args):
    t0 = time.time()
    try:
        r = fn(*args)
        STATUS["fases"][nome] = {"status": "ok", "segundos": round(time.time() - t0, 1)}
        return r
    except Exception:
        tb = traceback.format_exc()
        STATUS["fases"][nome] = {"status": "erro", "segundos": round(time.time() - t0, 1),
                                 "erro": tb.strip().splitlines()[-1]}
        write(f"erro_fase_{nome}.txt", tb)
        return None


def sem_tags(txt):
    try:
        return ida_lines.tag_remove(txt)
    except Exception:
        return txt


# ---------------------------------------------------------------------------
# Nomes
# ---------------------------------------------------------------------------
def demangle(nome):
    if not nome:
        return None
    try:
        if nome.startswith("?") or nome.startswith("_Z") or nome.startswith("__Z"):
            d = ida_name.demangle_name(nome, ida_name.MNG_SHORT_FORM)
            if d:
                return d
    except Exception:
        pass
    d, _ = ac.demangle_fortran(nome)
    return d


# ---------------------------------------------------------------------------
# Fase: funcoes, imports, exports
# ---------------------------------------------------------------------------
def coletar_imports():
    for i in range(ida_nalt.get_import_module_qty()):
        dll = ida_nalt.get_import_module_name(i) or ""

        def cb(ea, name, ordinal, dll=dll):
            IMPORTS[ea] = (dll, name or "", ordinal)
            return True

        ida_nalt.enum_import_names(i, cb)


def coletar_exports():
    global ENTRY_EA
    for idx in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(idx)
        ea = ida_entry.get_entry(ordinal)
        if ea == BADADDR:
            fwd = ""
            try:
                fwd = ida_entry.get_entry_forwarder(ordinal) or ""
            except Exception:
                pass
            if fwd:
                EXPORTS.append({"ordinal": ordinal, "ea": None, "name": ida_entry.get_entry_name(ordinal) or "",
                                "forwarder": fwd})
            continue
        nome = ida_entry.get_entry_name(ordinal) or ""
        if ordinal == ea:            # o PE loader marca o entry point com ordinal == ea
            ENTRY_EA = ea
            continue
        EXPORTS.append({"ordinal": ordinal, "ea": ea, "name": nome, "forwarder": ""})
    if ENTRY_EA is None:
        try:
            e = ida_ida.inf_get_start_ip()
            if e not in (None, BADADDR):
                ENTRY_EA = e
        except Exception:
            pass


def coletar_funcoes():
    exp_por_ea = collections.defaultdict(list)
    for e in EXPORTS:
        if e["ea"] is not None:
            fn = ida_funcs.get_func(e["ea"])
            exp_por_ea[fn.start_ea if fn else e["ea"]].append(e)
    for ea in idautils.Functions():
        fn = ida_funcs.get_func(ea)
        if not fn:
            continue
        nome = ida_funcs.get_func_name(ea)
        dem = demangle(nome)
        F[ea] = {
            "ea": ea, "end": fn.end_ea, "size": fn.end_ea - ea,
            "name": nome, "name_original": nome, "demangled": dem,
            "lib": bool(fn.flags & ida_funcs.FUNC_LIB),
            "thunk": bool(fn.flags & ida_funcs.FUNC_THUNK),
            "noret": bool(fn.flags & ida_funcs.FUNC_NORET),
            "exported": ea in exp_por_ea,
            "export_ordinals": [e["ordinal"] for e in exp_por_ea.get(ea, [])],
            "kind": "", "nivel": None, "grupo": None, "recursivo": False,
            "callees": set(), "callers": set(), "externs": set(), "globals": {},
            "strings": [], "indirect_calls": 0, "nblocks": None, "virtual": False,
            "decompilado": False, "arquivo": None, "proto": None, "falha": None,
        }


# ---------------------------------------------------------------------------
# Fase: RTTI / vtables (antes do rename: precisa dos nomes mangled)
# ---------------------------------------------------------------------------
def _ler_ptr(ea):
    return ida_bytes.get_qword(ea) if IS64 else ida_bytes.get_dword(ea)


def _nome_rtti(s):
    s = s.strip()
    for pre in (".?AV", ".?AU", ".?AW4", ".?AT"):
        if s.startswith(pre):
            s = s[len(pre):]
            break
    s = s[:-2] if s.endswith("@@") else s
    partes = [p for p in s.split("@") if p]
    return "::".join(reversed(partes)) or s


def _str_c(ea, maximo=256):
    out = bytearray()
    for i in range(maximo):
        b = ida_bytes.get_byte(ea + i)
        if b == 0:
            break
        out.append(b)
    return out.decode("latin-1")


def _entradas_vtable(ini, fim_seg):
    entradas = []
    ea = ini
    for i in range(512):
        if ea + PTR > fim_seg:
            break
        if i > 0 and ida_name.get_name(ea):
            break
        p = _ler_ptr(ea)
        fn = ida_funcs.get_func(p) if p not in (0, BADADDR) else None
        if not fn or fn.start_ea != p:
            break
        entradas.append({"indice": i, "ea": p, "name": ida_funcs.get_func_name(p)})
        ea += PTR
    return entradas


def _bases_msvc(col, base):
    """Le Class Hierarchy Descriptor a partir do Complete Object Locator."""
    sig = ida_bytes.get_dword(col)
    off = ida_bytes.get_dword(col + 4)
    if sig == 1:
        td = base + ida_bytes.get_dword(col + 12)
        chd = base + ida_bytes.get_dword(col + 16)
    else:
        td = ida_bytes.get_dword(col + 12)
        chd = ida_bytes.get_dword(col + 16)
    nome = _nome_rtti(_str_c(td + 2 * PTR))
    n = ida_bytes.get_dword(chd + 8)
    arr = ida_bytes.get_dword(chd + 12)
    arr = base + arr if sig == 1 else arr
    bases = []
    for i in range(min(n, 64)):
        bcd = ida_bytes.get_dword(arr + 4 * i)
        bcd = base + bcd if sig == 1 else bcd
        btd = ida_bytes.get_dword(bcd)
        btd = base + btd if sig == 1 else btd
        bn = _nome_rtti(_str_c(btd + 2 * PTR))
        if bn != nome:
            bases.append(bn)
    return nome, off, bases


def rtti():
    base = ida_nalt.get_imagebase()
    classes = []
    for ea, nome in idautils.Names():
        try:
            dem = ida_name.demangle_name(nome, ida_name.MNG_LONG_FORM) if (nome.startswith("?") or nome.startswith("_Z")) else None
        except Exception:
            dem = None
        if not dem:
            continue
        seg = ida_segment.getseg(ea)
        fim = seg.end_ea if seg else ea
        reg = None
        if "`vftable'" in dem:
            cls, off, bases = dem.replace("const ", "").split("::`vftable'")[0], 0, []
            try:
                col = _ler_ptr(ea - PTR)
                if ida_segment.getseg(col):
                    cls, off, bases = _bases_msvc(col, base)
            except Exception:
                pass
            reg = {"abi": "msvc", "class": cls, "vtable_ea": ea, "offset_in_object": off,
                   "bases": bases, "entradas": _entradas_vtable(ea, fim), "simbolo": nome}
        elif dem.startswith("vtable for "):
            reg = {"abi": "itanium", "class": dem[len("vtable for "):], "vtable_ea": ea,
                   "offset_in_object": 0, "bases": [],
                   "entradas": _entradas_vtable(ea + 2 * PTR, fim), "simbolo": nome}
        if reg and reg["entradas"]:
            classes.append(reg)
            for e in reg["entradas"]:
                if e["ea"] in F:
                    F[e["ea"]]["virtual"] = True
    ac.gravar_json(os.path.join(OUT, "classes_rtti.json"), classes)
    L = ["// Esqueleto de classes recuperado de RTTI/vtables (so assinaturas simbolicas).",
         "// Preencher tipos de retorno/argumentos a partir do pseudocodigo.", ""]
    for c in classes:
        nome = ac.identificador_c(c["class"])
        bases = ", ".join("public " + ac.identificador_c(b) for b in c["bases"])
        L.append(f"// vtable @ 0x{c['vtable_ea']:X}  ({c['abi']})  nome original: {c['class']}")
        L.append(f"struct {nome}" + (f" : {bases}" if bases else "") + " {")
        for e in c["entradas"]:
            L.append(f"    virtual void vf{e['indice']}();   // 0x{e['ea']:X} {e['name']}")
        L.append("};\n")
    write("classes_skeleton.hpp", "\n".join(L))
    STATUS["classes_rtti"] = len(classes)


# ---------------------------------------------------------------------------
# Fase: renomear simbolos nao validos em C (para o pseudocodigo compilar)
# ---------------------------------------------------------------------------
def renomear():
    usados = set()
    for ea, info in F.items():
        if ac.nome_valido_c(info["name"]):
            usados.add(info["name"])
    linhas = []
    for ea in sorted(F):
        info = F[ea]
        if ac.nome_valido_c(info["name"]):
            continue
        base = info["demangled"] or info["name"]
        novo = ac.identificador_c(base, usados)
        try:
            flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE
            if ida_name.set_name(ea, novo, flags):
                linhas.append([f"0x{ea:X}", info["name"], novo])
                info["name"] = novo
        except Exception:
            pass
    ac.gravar_csv(os.path.join(OUT, "renomeacoes.csv"), ["ea", "nome_original", "nome_c"], linhas)


# ---------------------------------------------------------------------------
# Fase: grafo de chamadas, referencias a dados/strings, ISA
# ---------------------------------------------------------------------------
_X87_EXCL = {"fxsave", "fxrstor", "fxsave64", "fxrstor64", "femms"}
_SSE_SUF = ("sd", "ss", "pd", "ps")


def contar_isa(mnem):
    if not mnem:
        return
    m = mnem.lower()
    if m.startswith("vfm") or m.startswith("vfnm"):
        ISA["fma"] += 1
    elif m.startswith("v") and m not in ("verr", "verw", "vmcall", "vmlaunch"):
        ISA["avx"] += 1
    elif m.startswith("f") and m not in _X87_EXCL:
        ISA["x87"] += 1
    elif m.endswith(_SSE_SUF) or m in ("movaps", "movups", "movdqa", "movdqu", "pxor", "andps", "xorps"):
        ISA["sse"] += 1


def _texto_string(ea):
    try:
        b = idc.get_strlit_contents(ea)
        if b:
            return b.decode("utf-8", "replace")[:80]
    except Exception:
        pass
    return ""


CODE_REFS = (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF)
DATA_REFS = (ida_xref.dr_O, ida_xref.dr_R, ida_xref.dr_W)


def construir_grafo():
    o_reg, o_phrase, o_displ = idc.o_reg, idc.o_phrase, idc.o_displ
    for ea, info in F.items():
        for head in idautils.FuncItems(ea):
            mnem = idc.print_insn_mnem(head)
            contar_isa(mnem)
            if mnem == "call":
                try:
                    if idc.get_operand_type(head, 0) in (o_reg, o_phrase, o_displ):
                        info["indirect_calls"] += 1
                except Exception:
                    pass
            for x in idautils.XrefsFrom(head, 0):
                alvo = x.to
                if x.type in CODE_REFS:
                    if alvo in IMPORTS:
                        info["externs"].add("%s!%s" % (IMPORTS[alvo][0], IMPORTS[alvo][1] or "#%d" % IMPORTS[alvo][2]))
                        continue
                    fn = ida_funcs.get_func(alvo)
                    if fn and fn.start_ea != ea and fn.start_ea in F:
                        info["callees"].add(fn.start_ea)
                elif x.type in DATA_REFS:
                    if alvo in IMPORTS:
                        info["externs"].add("%s!%s" % (IMPORTS[alvo][0], IMPORTS[alvo][1] or "#%d" % IMPORTS[alvo][2]))
                        continue
                    if alvo in F:                      # endereco de funcao tomado (callback/ponteiro)
                        if alvo != ea:
                            info["callees"].add(alvo)
                        continue
                    flags = ida_bytes.get_flags(alvo)
                    if ida_bytes.is_strlit(flags):
                        if len(info["strings"]) < 12:
                            info["strings"].append([alvo, _texto_string(alvo)])
                    elif ida_bytes.is_data(flags) or not ida_bytes.is_code(flags):
                        modo = {ida_xref.dr_R: "r", ida_xref.dr_W: "w", ida_xref.dr_O: "o"}[x.type]
                        atual = info["globals"].get(alvo, "")
                        if modo not in atual:
                            info["globals"][alvo] = atual + modo
    for ea, info in F.items():
        for c in info["callees"]:
            F[c]["callers"].add(ea)


# ---------------------------------------------------------------------------
# Fase: classificar (usuario x biblioteca) + ordem folhas-primeiro
# ---------------------------------------------------------------------------
def classificar():
    grafo = {ea: set(i["callees"]) for ea, i in F.items()}
    raizes_exp = [e for e, i in F.items() if i["exported"]]
    alc_exp = ac.alcancaveis(grafo, raizes_exp)
    alc_entry = ac.alcancaveis(grafo, [ENTRY_EA] if ENTRY_EA in F else [])
    for ea, i in F.items():
        if i["exported"]:
            i["kind"] = "user"
        elif i["lib"]:
            i["kind"] = "lib"
        elif i["thunk"]:
            i["kind"] = "thunk"
        elif ac.nome_de_runtime(i["name_original"], i["demangled"]) or ac.nome_de_runtime(i["name"], i["demangled"]):
            i["kind"] = "runtime"
        elif ea in alc_exp:
            i["kind"] = "user"
        elif ea in alc_entry and not i["virtual"]:
            i["kind"] = "init"         # DllMain / inicializacao: pode ser CRT ou codigo do autor
        else:
            i["kind"] = "orphan"       # chamada por ponteiro/vtable/callback
    usuario = {ea for ea, i in F.items() if i["kind"] in ("user", "init", "orphan")}
    sub = {ea: {c for c in F[ea]["callees"] if c in usuario} for ea in usuario}
    info, ordem = ac.ordem_folhas_primeiro(sub)
    for ea, d in info.items():
        F[ea]["nivel"], F[ea]["grupo"], F[ea]["recursivo"] = d["nivel"], d["grupo"], d["recursivo"]
    return ordem


def nome_curto(ea):
    return F[ea]["name"] if ea in F else f"0x{ea:X}"


def escrever_grafo(ordem):
    nos = []
    arestas = []
    for ea in sorted(F):
        i = F[ea]
        nos.append({
            "ea": f"0x{ea:X}", "name": i["name"], "name_original": i["name_original"],
            "demangled": i["demangled"], "kind": i["kind"], "size": i["size"],
            "nivel": i["nivel"], "recursivo": i["recursivo"], "exported": i["exported"],
            "callees": [f"0x{c:X}" for c in sorted(i["callees"])],
            "callers": [f"0x{c:X}" for c in sorted(i["callers"])],
            "externs": sorted(i["externs"]), "indirect_calls": i["indirect_calls"],
        })
        for c in sorted(i["callees"]):
            arestas.append([i["name"], f"0x{ea:X}", nome_curto(c), f"0x{c:X}"])
    ac.gravar_json(os.path.join(OUT, "callgraph.json"), {"dll": NOME_DLL, "nos": nos})
    ac.gravar_csv(os.path.join(OUT, "callgraph_edges.csv"),
                  ["chamador", "ea_chamador", "chamado", "ea_chamado"], arestas)
    linhas = []
    for pos, ea in enumerate(ordem, 1):
        i = F[ea]
        linhas.append([pos, i["nivel"], f"0x{ea:X}", i["name"], i["kind"], i["size"],
                       "sim" if i["recursivo"] else "", i["grupo"],
                       ";".join(nome_curto(c) for c in sorted(i["callees"]) if c in F and F[c]["kind"] in ("user", "init", "orphan"))])
    ac.gravar_csv(os.path.join(OUT, "ordem_reescrita.csv"),
                  ["ordem", "nivel(0=folha)", "ea", "nome", "tipo", "tamanho", "recursivo", "grupo_scc", "chama"], linhas)
    lib = [f"0x{ea:016X} {F[ea]['kind']:8s} size={F[ea]['size']:6d} {F[ea]['name']}"
           for ea in sorted(F) if F[ea]["kind"] in ("lib", "thunk", "runtime")]
    write("funcoes_biblioteca.txt", "# Funcoes FLIRT (FUNC_LIB), thunks e runtime reconhecido por nome\n" + "\n".join(lib) + "\n")


# ---------------------------------------------------------------------------
# Prototipos
# ---------------------------------------------------------------------------
def _cc_nome(cc):
    cc &= ida_typeinf.CM_CC_MASK
    for n in ("CDECL", "STDCALL", "PASCAL", "FASTCALL", "THISCALL", "SWIFT", "GOLANG",
              "USERCALL", "USERPURGE", "SPECIAL", "SPECIALE", "SPECIALP", "ELLIPSIS", "VOIDARG"):
        v = getattr(ida_typeinf, "CM_CC_" + n, None)
        if v is not None and v == cc:
            return "__" + n.lower()
    return f"cc_0x{cc:X}"


def _tif_decl(tif, nome):
    try:
        s = tif._print(nome, ida_typeinf.PRTYPE_1LINE)
        if s:
            return sem_tags(s)
    except Exception:
        pass
    try:
        return sem_tags(str(tif))
    except Exception:
        return None


def prototipo(ea, cfunc=None):
    tif = ida_typeinf.tinfo_t()
    fonte = None
    if cfunc is not None:
        try:
            if cfunc.get_func_type(tif):
                fonte = "hexrays"
        except Exception:
            pass
    if fonte is None:
        try:
            if ida_nalt.get_tinfo(tif, ea):
                fonte = "tipo_ida"
        except Exception:
            pass
    nome = F[ea]["name"] if ea in F else ida_funcs.get_func_name(ea)
    if fonte is None:
        try:
            d = idc.get_type(ea) or idc.guess_type(ea)
        except Exception:
            d = None
        return {"decl": d, "ret": None, "cc": None, "nargs": None, "args": [], "fonte": "guess" if d else None}
    res = {"decl": _tif_decl(tif, nome), "ret": None, "cc": None, "nargs": None, "args": [], "fonte": fonte}
    try:
        ftd = ida_typeinf.func_type_data_t()
        if tif.get_func_details(ftd):
            res["cc"] = _cc_nome(ftd.cc)
            res["ret"] = sem_tags(str(ftd.rettype))
            res["nargs"] = ftd.size()
            for k in range(ftd.size()):
                res["args"].append({"tipo": sem_tags(str(ftd[k].type)), "nome": ftd[k].name})
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# Fase: decompilar (um arquivo por funcao, folhas primeiro)
# ---------------------------------------------------------------------------
def cabecalho_funcao(ea):
    i = F[ea]
    L = ["/*",
         f" * Funcao   : {i['name']}",
         f" * Original : {i['name_original']}" + (f"   ({i['demangled']})" if i["demangled"] else ""),
         f" * EA / tam : 0x{ea:X} / {i['size']} bytes",
         f" * Tipo     : {i['kind']}" + ("  [exportada ord=%s]" % ",".join(map(str, i["export_ordinals"])) if i["exported"] else "")
         + ("  [virtual]" if i["virtual"] else "") + ("  [RECURSIVA/ciclo]" if i["recursivo"] else ""),
         f" * Nivel    : {i['nivel']} (0 = folha; reescrever em ordem crescente)"]
    cal = [nome_curto(c) for c in sorted(i["callees"])]
    if cal:
        L.append(" * Chama    : " + ", ".join(cal[:30]) + (" ..." if len(cal) > 30 else ""))
    if i["externs"]:
        ex = sorted(i["externs"])
        L.append(" * Externos : " + ", ".join(ex[:20]) + (" ..." if len(ex) > 20 else ""))
    if i["globals"]:
        gl = [f"{ida_name.get_name(a) or hex(a)}({m})" for a, m in sorted(i["globals"].items())[:20]]
        L.append(" * Globais  : " + ", ".join(gl) + (" ..." if len(i["globals"]) > 20 else ""))
    if i["strings"]:
        L.append(" * Strings  : " + " | ".join(repr(s[1]) for s in i["strings"][:6]))
    if i["indirect_calls"]:
        L.append(f" * Chamadas indiretas: {i['indirect_calls']} (ponteiro/vtable)")
    L.append(" */")
    return "\n".join(L)


def _valor_item(alvo, mnem):
    """Valor de uma constante lida de memoria (double/float/inteiro) para anotar o asm."""
    try:
        import struct
        seg = ida_segment.getseg(alvo)
        if seg is None or (seg.perm & ida_segment.SEGPERM_EXEC):
            return ""
        fl = ida_bytes.get_flags(alvo)
        m = (mnem or "").lower()
        if ida_bytes.is_double(fl) or m.endswith(("sd", "pd")):
            raw = ida_bytes.get_bytes(alvo, 8)
            return "= double " + repr(struct.unpack("<d", raw)[0]) if raw and len(raw) == 8 else ""
        if ida_bytes.is_float(fl) or m.endswith(("ss", "ps")):
            raw = ida_bytes.get_bytes(alvo, 4)
            return "= float " + repr(struct.unpack("<f", raw)[0]) if raw and len(raw) == 4 else ""
        if ida_bytes.is_qword(fl):
            return "= qword 0x%X" % ida_bytes.get_qword(alvo)
        if ida_bytes.is_dword(fl):
            return "= dword 0x%X" % ida_bytes.get_dword(alvo)
    except Exception:
        pass
    return ""


def _comentarios_insn(h, ea_func, mnem):
    cm = []
    for x in idautils.XrefsFrom(h, 0):
        alvo = x.to
        if x.type in CODE_REFS:
            if alvo in IMPORTS:
                cm.append("-> %s!%s" % (IMPORTS[alvo][0], IMPORTS[alvo][1] or "#%d" % IMPORTS[alvo][2]))
                continue
            fn = ida_funcs.get_func(alvo)
            if fn and fn.start_ea != ea_func:
                nome = F[fn.start_ea]["name"] if fn.start_ea in F else ida_funcs.get_func_name(fn.start_ea)
                kind = F[fn.start_ea]["kind"] if fn.start_ea in F else "?"
                cm.append("-> %s [%s]" % (nome, kind))
        elif x.type in DATA_REFS:
            if alvo in IMPORTS:
                cm.append("-> %s!%s" % (IMPORTS[alvo][0], IMPORTS[alvo][1]))
            elif alvo in F:
                cm.append("&%s" % F[alvo]["name"])
            elif ida_bytes.is_strlit(ida_bytes.get_flags(alvo)):
                cm.append("str %r" % _texto_string(alvo))
            else:
                nm = ida_name.get_name(alvo) or ("0x%X" % alvo)
                cm.append(("[%s] %s" % (nm, _valor_item(alvo, mnem))).strip())
    return cm


def _blocos(ea):
    fn = ida_funcs.get_func(ea)
    try:
        return sorted((b.start_ea, b.end_ea, [p.start_ea for p in b.preds()], [q.start_ea for q in b.succs()])
                      for b in ida_gdl.FlowChart(fn))
    except Exception:
        return [(fn.start_ea, fn.end_ea, [], [])]


def asm_anotado(ea):
    """Disassembly por bloco basico, com preds/succs e comentarios: chamadas resolvidas,
    imports, strings e constantes double/float lidas da memoria. Fallback quando o Hex-Rays falha."""
    itens = list(idautils.FuncItems(ea))
    linhas = []
    k = 0
    for ini, fim, preds, succs in _blocos(ea):
        linhas.append("; ---- bloco 0x%X  preds=[%s]  succs=[%s]" % (
            ini, ",".join("0x%X" % p for p in preds), ",".join("0x%X" % q for q in succs)))
        while k < len(itens) and itens[k] < ini:
            k += 1
        while k < len(itens) and itens[k] < fim:
            h = itens[k]
            k += 1
            try:
                txt = sem_tags(ida_lines.generate_disasm_line(h, 0))
            except Exception:
                txt = "; (falha ao desmontar)"
            try:
                cm = _comentarios_insn(h, ea, idc.print_insn_mnem(h))
            except Exception:
                cm = []
            linhas.append("%016X  %-48s%s" % (h, txt, ("  ; " + " | ".join(cm)) if cm else ""))
    return "\n".join(linhas) + "\n"


def nblocks(ea):
    try:
        return ida_gdl.FlowChart(ida_funcs.get_func(ea)).size
    except Exception:
        try:
            return len(list(ida_gdl.FlowChart(ida_funcs.get_func(ea))))
        except Exception:
            return None


INCLUDES = ('#include "../include/defs.h"   /* copiado de <IDA>\\plugins\\defs.h */\n'
            '#include "../include/tipos.h"\n'
            '#include "../include/funcoes.h"\n')


def decompilar(ordem):
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        aviso("Hex-Rays nao disponivel para esta arquitetura.")
        write("pseudocode_hexrays.c", "Hex-Rays nao disponivel.\n")
        STATUS["hexrays"] = False
        return
    STATUS["hexrays"] = True
    usados = set()
    alvos = [(ea, SRC) for ea in ordem]
    if DECOMPILAR_LIB:
        os.makedirs(LIBDIR, exist_ok=True)
        alvos += [(ea, LIBDIR) for ea in sorted(F) if F[ea]["kind"] in ("lib", "runtime")]
    ok = bad = pulados = 0
    f_all = open(os.path.join(OUT, "pseudocode_hexrays.c"), "w", encoding="utf-8", errors="replace")
    f_fail = open(os.path.join(OUT, "decompile_failures.txt"), "w", encoding="utf-8", errors="replace")
    f_all.write("/* PSEUDOCODIGO HEX-RAYS - SOMENTE CODIGO DO USUARIO, folhas primeiro.\n"
                "   Funcoes de biblioteca/thunks: ver funcoes_biblioteca.txt.\n"
                "   NAO E O CODIGO FONTE ORIGINAL. */\n\n")
    f_fail.write("# 1a passada (ANTES do retry): ea | nome | tipo | tamanho | motivo. Lista final: falhas_priorizadas.csv\n")
    ordem_arq = []
    try:
        for n, (ea, pasta) in enumerate(alvos):
            i = F[ea]
            arq = ac.nome_arquivo_seguro(i["name"], usados, ea)
            if prazo_estourado():
                pulados += 1
                i["falha"] = "prazo (IDA_SOFT_DEADLINE) esgotado antes de decompilar"
                f_fail.write(f"0x{ea:016X} | {i['name']} | {i['kind']} | {i['size']} | {i['falha']}\n")
                if pasta == SRC:
                    FALHAS[ea] = {"motivo": i["falha"], "arq": arq}
                continue
            i["nblocks"] = nblocks(ea)
            try:
                cf = ida_hexrays.decompile(ea)
                if cf is None:
                    raise RuntimeError("decompile() retornou None")
                corpo = sem_tags(str(cf))
                i["proto"] = prototipo(ea, cf)
                i["decompilado"] = True
                caminho = os.path.join(pasta, arq + ".c")
                with open(caminho, "w", encoding="utf-8", errors="replace") as f:
                    f.write(cabecalho_funcao(ea) + "\n" + INCLUDES + "\n" + corpo + "\n")
                i["arquivo"] = os.path.relpath(caminho, OUT)
                if pasta == SRC:
                    f_all.write("\n" + "=" * 100 + f"\n// EA: 0x{ea:016X}\n// NAME: {i['name']}\n"
                                + "=" * 100 + "\n" + corpo + "\n")
                    ordem_arq.append(arq)
                ok += 1
            except Exception as e:
                motivo = str(e) or type(e).__name__
                errea = getattr(e, "errea", None)
                if errea not in (None, BADADDR):
                    motivo += f" (em 0x{errea:X})"
                i["falha"] = motivo
                i["proto"] = i["proto"] or prototipo(ea)
                try:
                    asm = asm_anotado(ea)
                except Exception:
                    asm = asm_da_funcao_simples(ea)
                write(arq + ".asm", asm, ASMDIR)
                caminho = os.path.join(pasta, arq + ".c")
                with open(caminho, "w", encoding="utf-8", errors="replace") as f:
                    f.write(cabecalho_funcao(ea) + "\n" + INCLUDES
                            + f"\n/* FALHA NO DECOMPILADOR: {motivo}\n   Disassembly anotado (tambem em asm\\{arq}.asm):\n"
                            + asm.replace("*/", "* /") + "*/\n")
                i["arquivo"] = os.path.relpath(caminho, OUT)
                f_fail.write(f"0x{ea:016X} | {i['name']} | {i['kind']} | {i['size']} | {motivo}\n")
                f_fail.flush()
                if pasta == SRC:
                    bad += 1
                    FALHAS[ea] = {"motivo": motivo, "arq": arq}
            if n % 50 == 0:
                f_all.flush()
    finally:
        f_all.write(f"\n// Funcoes decompiladas: {ok}\n// Falhas: {bad}\n// Puladas por prazo: {pulados}\n")
        f_all.close()
        f_fail.write(f"\n# total falhas={bad} puladas_por_prazo={pulados}\n")
        f_fail.close()
    write("src_ordem.txt", "\n".join(f"{k:05d} {a}.c" for k, a in enumerate(ordem_arq, 1)) + "\n", SRC)
    ORDEM_ARQ[:] = ordem_arq
    STATUS.update({"decompiladas": ok, "falhas_decompilador": bad, "puladas_prazo": pulados})


def asm_da_funcao_simples(ea):
    linhas = []
    for h in idautils.FuncItems(ea):
        try:
            linhas.append(f"{h:016X}  {sem_tags(ida_lines.generate_disasm_line(h, 0))}")
        except Exception:
            linhas.append(f"{h:016X}  ; (falha ao desmontar)")
    return "\n".join(linhas) + "\n"


def exemplos_de_chamada(ea, limite=6):
    """Linhas dos chamadores (ja decompilados) que chamam a funcao: mostram nº/tipo de argumentos."""
    nome = F[ea]["name"]
    rx = re.compile(r"\b" + re.escape(nome) + r"\s*\(")
    ex = []
    for c in sorted(F[ea]["callers"]):
        arq = F[c].get("arquivo")
        if not arq or not F[c]["decompilado"]:
            continue
        try:
            with open(os.path.join(OUT, arq), encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    t = ln.strip()
                    if rx.search(t) and not t.startswith(("/*", "*", "//", "#")):
                        ex.append(f"{F[c]['name']}: {t[:160]}")
                        if len(ex) >= limite:
                            return ex
        except OSError:
            continue
    return ex


def tratar_falhas():
    """1) tenta recuperar (reanalisa a funcao e decompila de novo); 2) enriquece o que continua
    falhando (categoria, sugestao, impacto, exemplos de chamada); 3) gera a lista priorizada."""
    import ida_hexrays
    if not FALHAS:
        STATUS.update({"recuperadas_retry": 0, "falhas_por_categoria": {}})
        return
    recuperadas = []
    if STATUS.get("hexrays"):
        for ea in list(FALHAS):
            if prazo_estourado():
                break
            if FALHAS[ea]["motivo"].startswith("prazo"):
                continue
            try:
                ida_funcs.reanalyze_function(ida_funcs.get_func(ea))
                ida_auto.auto_wait()
                cf = ida_hexrays.decompile(ea)
                if cf is None:
                    continue
                corpo = sem_tags(str(cf))
            except Exception:
                continue
            i = F[ea]
            i["proto"] = prototipo(ea, cf)
            i["decompilado"], i["falha"] = True, None
            caminho = os.path.join(SRC, FALHAS[ea]["arq"] + ".c")
            with open(caminho, "w", encoding="utf-8", errors="replace") as f:
                f.write(cabecalho_funcao(ea) + "\n" + INCLUDES + "\n/* recuperada no retry (funcao reanalisada) */\n" + corpo + "\n")
            with open(os.path.join(OUT, "pseudocode_hexrays.c"), "a", encoding="utf-8", errors="replace") as f:
                f.write("\n" + "=" * 100 + f"\n// EA: 0x{ea:016X}  (recuperada no retry)\n// NAME: {i['name']}\n"
                        + "=" * 100 + "\n" + corpo + "\n")
            try:
                os.remove(os.path.join(ASMDIR, FALHAS[ea]["arq"] + ".asm"))
            except OSError:
                pass
            recuperadas.append(ea)
            del FALHAS[ea]

    exportadas = {e for e, i in F.items() if i["exported"]}
    linhas, cont = [], collections.Counter()
    for ea, info in FALHAS.items():
        i = F[ea]
        cat, sug = ac.categoria_falha(info["motivo"])
        dep = ac.dependentes({k: v["callers"] for k, v in F.items()}, ea)
        afet = len((dep | {ea}) & exportadas)
        info.update({"categoria": cat, "sugestao": sug, "diretos": len(i["callers"]),
                     "dependentes": len(dep), "exports_afetados": afet})
        cont[cat] += 1
        if not info["motivo"].startswith("prazo"):      # prazo: sem .c com asm; novo run resolve
            ex = exemplos_de_chamada(ea)
            try:
                asm = open(os.path.join(ASMDIR, info["arq"] + ".asm"), encoding="utf-8", errors="replace").read()
            except OSError:
                asm = ""
            corpo = ["\n/* FALHA NO DECOMPILADOR",
                     f"   Motivo    : {info['motivo']}",
                     f"   Categoria : {cat}",
                     f"   Sugestao  : {sug}",
                     f"   Impacto   : {info['diretos']} chamador(es) direto(s); {info['dependentes']} funcao(oes) dependente(s); "
                     f"{afet} export(s) afetado(s)"]
            if ex:
                corpo.append("   Exemplos de chamada (nos chamadores decompilados) - use para inferir os argumentos:")
                corpo += [f"     {l.replace('*/', '* /')}" for l in ex]
            corpo.append("   Disassembly anotado (tambem em asm\\%s.asm):" % info["arq"])
            caminho = os.path.join(SRC, info["arq"] + ".c")
            with open(caminho, "w", encoding="utf-8", errors="replace") as f:
                f.write(cabecalho_funcao(ea) + "\n" + INCLUDES + "\n".join(corpo) + "\n" + asm.replace("*/", "* /") + "*/\n")
        linhas.append([ea, i, info])
    # priorizacao: exportadas e de maior impacto primeiro; a mesma prioridade -> menores primeiro
    linhas.sort(key=lambda t: (not t[1]["exported"], -t[2]["exports_afetados"], -t[2]["dependentes"], t[1]["size"]))
    ac.gravar_csv(os.path.join(OUT, "falhas_priorizadas.csv"),
                  ["prioridade", "ea", "nome", "tipo", "tamanho", "blocos", "categoria", "exportada",
                   "chamadores_diretos", "dependentes", "exports_afetados", "motivo", "sugestao", "arquivo"],
                  [[n, f"0x{ea:X}", i["name"], i["kind"], i["size"], i["nblocks"], inf["categoria"],
                    "sim" if i["exported"] else "", inf["diretos"], inf["dependentes"], inf["exports_afetados"],
                    inf["motivo"], inf["sugestao"], i["arquivo"]] for n, (ea, i, inf) in enumerate(linhas, 1)])
    ac.gravar_csv(os.path.join(OUT, "decompile_failures.csv"),
                  ["ea", "nome", "tipo", "tamanho", "blocos", "categoria", "motivo"],
                  [[f"0x{ea:X}", i["name"], i["kind"], i["size"], i["nblocks"], inf["categoria"], inf["motivo"]]
                   for ea, i, inf in sorted(linhas, key=lambda t: t[0])])
    resumo_txt = ["FALHAS DO DECOMPILADOR POR CATEGORIA (final, apos retry)", "=" * 60,
                  f"Recuperadas no retry: {len(recuperadas)}   Ainda falhando: {len(FALHAS)}", ""]
    for cat, n in cont.most_common():
        resumo_txt.append(f"{n:5d}  {cat}: {ac.categoria_falha('', cat)[1]}")
    write("falhas_resumo.txt", "\n".join(resumo_txt) + "\n")
    nbad = sum(1 for v in FALHAS.values() if not v["motivo"].startswith("prazo"))
    STATUS.update({"recuperadas_retry": len(recuperadas), "falhas_por_categoria": dict(cont),
                   "falhas_decompilador": nbad, "decompiladas": STATUS.get("decompiladas", 0) + len(recuperadas)})


def escrever_funcoes_h(ordem):
    L = ["/* Prototipos de todas as funcoes do usuario (folhas primeiro). Gerado pelo IDA. */",
         "/* Incluir defs.h e tipos.h ANTES deste arquivo (cada src\\*.c ja faz isso). */",
         "#ifndef FUNCOES_H", "#define FUNCOES_H", ""]
    for ea in ordem:
        i = F[ea]
        d = (i["proto"] or {}).get("decl")
        if d:
            L.append(f"{d};   /* 0x{ea:X} */")
        else:
            L.append(f"/* sem prototipo: {i['name']} @0x{ea:X} */")
    L += ["", "#endif", ""]
    write("funcoes.h", "\n".join(L), INC)


def exports_com_prototipos():
    res = []
    usados = set()
    for e in EXPORTS:
        ea = e["ea"]
        fn = ida_funcs.get_func(ea) if ea is not None else None
        regs = {"ordinal": e["ordinal"], "name": e["name"], "forwarder": e["forwarder"],
                "ea": f"0x{ea:X}" if ea is not None else None}
        if fn:
            i = F.get(fn.start_ea)
            nome_c = i["name"] if i else e["name"]
            regs.update({
                "c_name": nome_c,
                "demangled": i["demangled"] if i else demangle(e["name"]),
                "tipo": "funcao", "kind": i["kind"] if i else None,
                "decompilado": bool(i and i["decompilado"]),
                "arquivo": i["arquivo"] if i else None,
                "proto": (i["proto"] if i and i["proto"] else prototipo(fn.start_ea)),
            })
        else:
            regs.update({"c_name": ac.identificador_c(e["name"], usados) if e["name"] else None,
                         "tipo": "dado" if ea is not None else "forwarder", "proto": None})
            if ea is not None:
                regs["tamanho_item"] = ida_bytes.get_item_size(ea)
        res.append(regs)
    ac.gravar_json(os.path.join(OUT, "exports_prototypes.json"), res)
    return res


# ---------------------------------------------------------------------------
# Fase: dados globais, constantes e tabelas
# ---------------------------------------------------------------------------
SEGS_IGNORAR = {".pdata", ".xdata", ".reloc", ".rsrc", ".idata", ".didat", ".edata", ".gfids",
                ".00cfg", ".CRT$XCA", ".debug"}


def _tipo_dado(flags, tam):
    if ida_bytes.is_float(flags):
        return "float"
    if ida_bytes.is_double(flags):
        return "double"
    if ida_bytes.is_strlit(flags):
        return "string"
    if ida_bytes.is_qword(flags):
        return "qword"
    if ida_bytes.is_dword(flags):
        return "dword"
    if ida_bytes.is_word(flags):
        return "word"
    if ida_bytes.is_byte(flags):
        return "byte"
    return f"bytes[{tam}]"


def _funcs_que_usam(ea, limite=10):
    fs = set()
    n = 0
    for x in idautils.XrefsTo(ea, 0):
        n += 1
        fn = ida_funcs.get_func(x.frm)
        if fn:
            fs.add(fn.start_ea)
    nomes = [nome_curto(f) for f in sorted(fs)[:limite]]
    return n, nomes


def dados():
    import struct
    linhas = []
    constantes = []
    globais_c = ["/* Definicoes dos dados globais referenciados pelo pseudocodigo (valores iniciais do binario).",
                 "   ATENCAO: o layout/adjacencia original se perde; se o codigo faz aritmetica de",
                 "   ponteiro entre itens vizinhos, use os data\\<segmento>.bin como referencia. */",
                 '#include "../include/defs.h"', ""]
    total = 0
    usados_g = set()
    tabelas = []
    seg_info = []
    for k in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(k)
        if not seg:
            continue
        nome = ida_segment.get_segm_name(seg)
        executavel = bool(seg.perm & ida_segment.SEGPERM_EXEC)
        if executavel or nome in SEGS_IGNORAR or seg.type in (ida_segment.SEG_XTRN,):
            continue
        ini, fim = seg.start_ea, seg.end_ea
        seg_info.append((nome, ini, fim))
        e_const = not (seg.perm & ida_segment.SEGPERM_WRITE)
        raw = None
        if seg.type != ida_segment.SEG_BSS and (fim - ini) <= 256 * 1024 * 1024:
            raw = ida_bytes.get_bytes(ini, fim - ini)
            if raw:
                with open(os.path.join(DATADIR, ac.nome_arquivo_seguro(nome.lstrip(".")) + ".bin"), "wb") as f:
                    f.write(raw)
        ea = ini
        while ea != BADADDR and ea < fim and total < MAX_DATA_ITEMS:
            flags = ida_bytes.get_flags(ea)
            tam = max(1, ida_bytes.get_item_size(ea))
            if ida_bytes.is_tail(flags):
                ea = ida_bytes.next_head(ea, fim)
                continue
            total += 1
            nm = ida_name.get_name(ea) or ""
            tipo = _tipo_dado(flags, tam)
            nref, usuarios = _funcs_que_usam(ea)
            valor = ""
            ofs = ea - ini
            if raw and tipo in ("float", "double", "qword", "dword", "word", "byte") and ofs + tam <= len(raw):
                try:
                    if tipo == "double" and tam == 8:
                        valor = repr(struct.unpack_from("<d", raw, ofs)[0])
                    elif tipo == "float" and tam == 4:
                        valor = repr(struct.unpack_from("<f", raw, ofs)[0])
                    elif tam in (1, 2, 4, 8):
                        valor = str(int.from_bytes(raw[ofs:ofs + tam], "little"))
                except Exception:
                    pass
            hexv = raw[ofs:ofs + min(tam, 32)].hex() if raw and ofs + tam <= len(raw) else ""
            linhas.append([nome, f"0x{ea:X}", tam, nm, tipo, valor, nref, ";".join(usuarios), hexv])
            if tipo in ("float", "double"):
                constantes.append([f"0x{ea:X}", nm, tipo, valor, nref, ";".join(usuarios)])
            if nref and nm and not ida_bytes.is_strlit(flags) and raw and ofs + tam <= len(raw) and tam <= 1 << 20:
                cn = ac.identificador_c(nm, usados_g)
                cst = "const " if e_const else ""
                if tipo == "double" and tam == 8:
                    globais_c.append(f"{cst}double {cn} = {ac.literal_c_double(struct.unpack_from('<d', raw, ofs)[0])};")
                elif tipo == "float" and tam == 4:
                    globais_c.append(f"{cst}float {cn} = {repr(struct.unpack_from('<f', raw, ofs)[0])}f;")
                elif tam in (1, 2, 4, 8):
                    ctipo = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned __int64"}[tam]
                    globais_c.append(f"{cst}{ctipo} {cn} = 0x{int.from_bytes(raw[ofs:ofs + tam], 'little'):X};")
                else:
                    corpo = ", ".join(f"0x{b:02X}" for b in raw[ofs:ofs + tam])
                    globais_c.append(f"{cst}unsigned char {cn}[{tam}] = {{ {corpo} }};")
            ea = ida_bytes.next_head(ea, fim)
        # tabelas candidatas (coeficientes etc.)
        if raw:
            for desloc in ((0, 4) if not IS64 else (0,)):
                for t in ac.tabelas_candidatas(raw[desloc:], ini + desloc, minimo=4, largura=8):
                    t["segmento"] = nome
                    tabelas.append(t)
    # funcoes que usam cada tabela + saida
    vistos = set()
    linhas_t = []
    tabelas_c = ["/* Tabelas de doubles candidatas (coeficientes/constantes). Valores com 17 digitos. */",
                 '#include "../include/defs.h"', ""]
    for t in sorted(tabelas, key=lambda x: x["ea"]):
        if t["ea"] in vistos:
            continue
        vistos.add(t["ea"])
        usuarios = set()
        for k in range(min(t["n"], 512)):
            fs = _funcs_que_usam(t["ea"] + 8 * k, 6)[1]
            usuarios.update(fs)
        nm = ida_name.get_name(t["ea"]) or ""
        linhas_t.append([t["segmento"], f"0x{t['ea']:X}", t["tipo"], t["n"], nm, ";".join(sorted(usuarios)[:10]),
                         " ".join(ac.literal_c_double(v) for v in t["valores"][:8])])
        if usuarios:
            cn = ac.identificador_c(nm or f"tabela_{t['ea']:X}")
            vals = t["valores"][:50000]
            tabelas_c.append(f"/* 0x{t['ea']:X} em {t['segmento']}, usada por: {', '.join(sorted(usuarios)[:6])} */")
            tabelas_c.append(f"const double tab_{cn}[{len(vals)}] = {{")
            for k in range(0, len(vals), 4):
                tabelas_c.append("    " + ", ".join(ac.literal_c_double(v) for v in vals[k:k + 4]) + ",")
            tabelas_c.append("};\n")
    ac.gravar_csv(os.path.join(DATADIR, "data_globals.csv"),
                  ["segmento", "ea", "tamanho", "nome", "tipo", "valor", "n_xrefs", "usado_por", "bytes_hex"], linhas)
    ac.gravar_csv(os.path.join(DATADIR, "constantes_float.csv"),
                  ["ea", "nome", "tipo", "valor", "n_xrefs", "usado_por"], constantes)
    ac.gravar_csv(os.path.join(DATADIR, "tabelas_candidatas.csv"),
                  ["segmento", "ea", "tipo", "n_valores", "nome", "usada_por", "primeiros_valores"], linhas_t)
    write("tabelas.c", "\n".join(tabelas_c) + "\n", DATADIR)
    write("globais.c", "\n".join(globais_c) + "\n", DATADIR)
    write("segmentos_dados.txt", "\n".join(f"{n:12s} 0x{a:X}-0x{b:X} size={b - a}" for n, a, b in seg_info) + "\n", DATADIR)
    STATUS.update({"itens_dados": total, "tabelas_candidatas": len(linhas_t)})
    if total >= MAX_DATA_ITEMS:
        aviso(f"dump de dados truncado em {MAX_DATA_ITEMS} itens (IDA_MAX_DATA_ITEMS)")


# ---------------------------------------------------------------------------
# Tipos locais (structs/enums) -> tipos.h (best effort)
# ---------------------------------------------------------------------------
def tipos_locais():
    L = ["/* Tipos locais do IDA (structs/enums/typedefs). Best-effort: revisar. */",
         "#ifndef TIPOS_H", "#define TIPOS_H", ""]
    til = ida_typeinf.get_idati()
    try:
        limite = ida_typeinf.get_ordinal_limit(til)
    except Exception:
        limite = ida_typeinf.get_ordinal_count(til) + 1
    n = 0
    for k in range(1, limite):
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_numbered_type(til, k):
                continue
            nome = tif.get_type_name()
            if not nome:
                continue
            decl = tif._print(nome, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE |
                              ida_typeinf.PRTYPE_SEMI | ida_typeinf.PRTYPE_DEF)
            if decl:
                L.append(sem_tags(decl))
                L.append("")
                n += 1
        except Exception:
            continue
    L += ["#endif", ""]
    write("tipos.h", "\n".join(L), INC)
    STATUS["tipos_locais"] = n


# ---------------------------------------------------------------------------
# Saidas "classicas" (mantidas da versao anterior)
# ---------------------------------------------------------------------------
def txt_functions():
    a = []
    for ea in sorted(F):
        i = F[ea]
        a.append(f"0x{ea:016X} - 0x{i['end']:016X} size={i['size']:8d} {i['kind']:8s} nivel={i['nivel']} {i['name']}")
    write("functions.txt", "\n".join(a) + "\n")
    out = []
    for ea in sorted(F):
        i = F[ea]
        d = {k: (sorted(v) if isinstance(v, set) else v) for k, v in i.items()
             if k not in ("callees", "callers", "globals", "strings")}
        d["ea_hex"] = f"0x{ea:X}"
        out.append(d)
    ac.gravar_json(os.path.join(OUT, "functions.json"), out)


def txt_segments():
    a = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s:
            a.append(f"{ida_segment.get_segm_name(s):20s} 0x{s.start_ea:016X} - 0x{s.end_ea:016X} perm={s.perm}")
    write("segments.txt", "\n".join(a) + "\n")


def txt_imports():
    a = [f"{d}!{n} ordinal={o} ea=0x{ea:016X}" for ea, (d, n, o) in sorted(IMPORTS.items())]
    write("imports_ida.txt", "\n".join(a) + "\n")


def txt_exports():
    a = [f"ordinal={e['ordinal']} ea={('0x%016X' % e['ea']) if e['ea'] is not None else 'fwd'} name={e['name']}"
         + (f" -> {e['forwarder']}" if e["forwarder"] else "") for e in EXPORTS]
    write("exports_ida.txt", "\n".join(a) + "\n")


def txt_strings():
    a = []
    for s in idautils.Strings():
        try:
            a.append(f"0x{s.ea:016X}: {str(s)}")
        except Exception:
            pass
    write("strings.txt", "\n".join(a) + "\n")


def asm_completo():
    caminho = os.path.join(OUT, "disasm_completo.asm")
    ok = idc.gen_file(idc.OFILE_ASM, caminho, 0, BADADDR, 0)
    STATUS["disasm_completo"] = bool(ok)
    if not ok:
        aviso("gen_file(OFILE_ASM) falhou; usar asm\\ (so falhas) ou exportar manualmente no IDA")


# ---------------------------------------------------------------------------
def resumo():
    kinds = collections.Counter(i["kind"] for i in F.values())
    try:
        cc = ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id())
    except Exception:
        cc = None
    isa = dict(ISA)
    arch_flag = None
    if isa.get("fma"):
        arch_flag = "/arch:AVX2"
    elif isa.get("avx"):
        arch_flag = "/arch:AVX"
    elif IS64:
        arch_flag = "/arch:SSE2 (padrao x64)"
    elif isa.get("sse") and not isa.get("x87"):
        arch_flag = "/arch:SSE2"
    elif isa.get("x87"):
        arch_flag = "/arch:IA32 (x87: precisao estendida de 80 bits nos intermediarios)"
    dados_json = {
        "dll": ida_nalt.get_root_filename(),
        "sha256": (ida_nalt.retrieve_input_file_sha256() or b"").hex() if hasattr(ida_nalt, "retrieve_input_file_sha256") else "",
        "caminho": ida_nalt.get_input_file_path(),
        "saida": OUT,
        "bits": 64 if IS64 else 32,
        "processador": ida_ida.inf_get_procname(),
        "compilador_ida": cc,
        "funcoes": len(F),
        "funcoes_usuario": kinds["user"] + kinds["init"] + kinds["orphan"],
        "funcoes_por_tipo": dict(kinds),
        "funcoes_lib": kinds["lib"], "funcoes_thunk": kinds["thunk"], "funcoes_runtime": kinds["runtime"],
        "exports": len(EXPORTS),
        "imports": len(IMPORTS),
        "isa_contagem": isa,
        "flag_arch_sugerida": arch_flag,
        "segundos": round(time.time() - INICIO, 1),
        "hexrays": STATUS.get("hexrays"),
        "decompiladas": STATUS.get("decompiladas", 0),
        "falhas_decompilador": STATUS.get("falhas_decompilador", 0),
        "recuperadas_retry": STATUS.get("recuperadas_retry", 0),
        "falhas_por_categoria": STATUS.get("falhas_por_categoria", {}),
        "puladas_prazo": STATUS.get("puladas_prazo", 0),
        "classes_rtti": STATUS.get("classes_rtti", 0),
        "tabelas_candidatas": STATUS.get("tabelas_candidatas", 0),
        "itens_dados": STATUS.get("itens_dados", 0),
        "fases": STATUS["fases"],
        "avisos": STATUS["avisos"],
        "versao_pipeline": ac.VERSAO_PIPELINE,
    }
    erros = [n for n, f in STATUS["fases"].items() if f["status"] == "erro"]
    dados_json["status"] = "ok" if not erros and not dados_json["puladas_prazo"] else "parcial"
    ac.gravar_json(os.path.join(OUT, "analysis_summary.json"), dados_json)
    write("analysis_summary.txt",
          "ANALISE IDA PRO 9.1 (pipeline %s)\n===================\n" % ac.VERSAO_PIPELINE +
          f"DLL: {dados_json['dll']}\nCaminho: {dados_json['caminho']}\nSaida: {OUT}\n"
          f"Bits: {dados_json['bits']}  Processador: {dados_json['processador']}  Compilador(IDA): {cc}\n"
          f"Funcoes: {len(F)}  (usuario={dados_json['funcoes_usuario']} lib={kinds['lib']} "
          f"thunk={kinds['thunk']} runtime={kinds['runtime']})\n"
          f"Decompiladas: {dados_json['decompiladas']}  Falhas: {dados_json['falhas_decompilador']}  "
          f"Puladas por prazo: {dados_json['puladas_prazo']}\n"
          f"ISA: {isa}  -> {arch_flag}\n"
          f"Fases com erro: {erros or 'nenhuma'}\nAvisos: {STATUS['avisos'] or 'nenhum'}\n\n"
          "O pseudocodigo Hex-Rays e uma representacao aproximada e nao recupera o fonte original.\n")
    return dados_json


def main():
    rc = 0
    try:
        ida_auto.auto_wait()
        fase("imports", coletar_imports)
        fase("exports", coletar_exports)
        fase("funcoes", coletar_funcoes)
        fase("rtti", rtti)
        if RENOMEAR:
            fase("renomear", renomear)
        fase("grafo", construir_grafo)
        ordem = fase("classificar", classificar) or []
        fase("segments", txt_segments)
        fase("txt_imports", txt_imports)
        fase("txt_exports", txt_exports)
        fase("grafo_saida", escrever_grafo, ordem)
        fase("tipos", tipos_locais)
        fase("decompilar", decompilar, ordem)
        fase("tratar_falhas", tratar_falhas)
        fase("funcoes_h", escrever_funcoes_h, ordem)
        fase("exports_proto", exports_com_prototipos)
        fase("functions_txt", txt_functions)
        fase("dados", dados)
        fase("strings", txt_strings)
        if ASM_FULL:
            fase("asm_completo", asm_completo)
        s = resumo()
        print("ANALISE IDA CONCLUIDA:", s["status"], "| funcoes:", s["funcoes"],
              "| decompiladas:", s["decompiladas"], "| falhas:", s["falhas_decompilador"])
        print("Saida:", OUT)
    except Exception:
        write("ida_script_error.txt", traceback.format_exc())
        rc = 1
    finally:
        ida_pro.qexit(rc)


if __name__ == "__main__":
    main()
