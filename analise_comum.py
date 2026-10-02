# -*- coding: utf-8 -*-
"""
Funcoes puras (somente biblioteca padrao) compartilhadas pelos scripts:
  - analisar_ida.py      (roda DENTRO do IDA)
  - classificar_dll.py, gerar_projeto.py, orquestrar.py, comparar_dlls.py

Nao importa nada do IDA, para poder ser testado fora dele.
"""
import csv
import json
import math
import re
import struct

VERSAO_PIPELINE = "5.0"

# ---------------------------------------------------------------------------
# Nomes de arquivo
# ---------------------------------------------------------------------------
_RESERVADOS = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} \
    | {f"LPT{i}" for i in range(1, 10)}


def nome_arquivo_seguro(nome, usados=None, ea=None, limite=100):
    """Nome valido no Windows, unico (sem diferenciar maiusculas), sem extensao."""
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", nome or "")
    base = re.sub(r"[`'\s]+", "_", base).strip(" ._") or "sem_nome"
    if len(base) > limite:
        base = base[:limite]
    if base.upper() in _RESERVADOS:
        base = "_" + base
    if usados is not None:
        cand = base
        if cand.lower() in usados:
            suf = f"_{ea:X}" if ea is not None else "_1"
            cand = base[: max(1, limite - len(suf))] + suf
            n = 2
            while cand.lower() in usados:
                cand = f"{base[:limite - 10]}_{n}"
                n += 1
        usados.add(cand.lower())
        return cand
    return base


def identificador_c(nome, usados=None):
    """Transforma um nome qualquer (mangled, com ?@$ etc.) num identificador C valido."""
    n = re.sub(r"[^A-Za-z0-9_]", "_", nome or "")
    n = re.sub(r"_+", "_", n).strip("_") or "sem_nome"
    if n[0].isdigit():
        n = "_" + n
    if usados is not None:
        cand, k = n, 2
        while cand in usados:
            cand = f"{n}_{k}"
            k += 1
        usados.add(cand)
        n = cand
    return n


def nome_valido_c(nome):
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", nome or ""))


# ---------------------------------------------------------------------------
# Demangle de nomes Fortran (IDA so demangla C++)
# ---------------------------------------------------------------------------
_RE_IFORT_MOD = re.compile(r"^(?P<mod>[A-Za-z0-9_$]+?)_[Mm][Pp]_(?P<proc>[A-Za-z0-9_$]+?)_?$")
_RE_GFORT_MOD = re.compile(r"^_{1,2}(?P<mod>[A-Za-z0-9_$]+?)_MOD_(?P<proc>[A-Za-z0-9_$]+)$")
_RE_GFORT_MAIN = re.compile(r"^_gfortran_[A-Za-z0-9_]+$")
_RE_FORTRAN_PLAIN = re.compile(r"^[A-Za-z][A-Za-z0-9$]*_$")


def demangle_fortran(nome):
    """Retorna (demangled, estilo) ou (None, None)."""
    if not nome:
        return None, None
    m = _RE_GFORT_MOD.match(nome)
    if m:
        return f"{m.group('mod')}::{m.group('proc')}", "gfortran"
    m = _RE_IFORT_MOD.match(nome)
    if m:
        return f"{m.group('mod')}::{m.group('proc')}", "ifort"
    return None, None


def parece_fortran(nome):
    d, _ = demangle_fortran(nome)
    return bool(d) or bool(_RE_FORTRAN_PLAIN.match(nome or ""))


# ---------------------------------------------------------------------------
# Heuristica de codigo de biblioteca/runtime (alem do FLIRT)
# ---------------------------------------------------------------------------
PADROES_RUNTIME = [
    r"^_?_?scrt_", r"^_?_?security_", r"^_?_?GSHandler", r"^_?_?report_gsfailure",
    r"^_?_?chkstk", r"^_?_?alloca_probe", r"^_?_?CxxFrameHandler", r"^_?_?C_specific_handler",
    r"^_?_?GSHandlerCheck", r"^_?_?guard_", r"^_?_?RTC_", r"^_?_?acrt_", r"^_?_?vcrt_",
    r"^_?_?intel_", r"^_?_?libm_", r"^_?_?svml_", r"^_?_?libirc_", r"^_?_?for_",
    r"^_?for_", r"^_?_?DllMainCRTStartup", r"^_?_?CRT_INIT", r"^_?_?initterm",
    r"^_?_?onexit", r"^_?_?atexit", r"^_?_?tmainCRTStartup", r"^_?_?DllMainCRTStartup",
    r"^_?_?imp_", r"^_?_?Init_thread", r"^_?_?std_", r"^_?_?gfortran", r"^_?_?mingw",
    r"^_?_?do_global", r"^_?_?gcc_", r"^_?_?cxa_", r"^_?_?dyn_tls", r"^_?_?tls_",
    r"^_?_?EH_", r"^_?_?unwind", r"^_?_?stack_chk", r"^_?_?DllEntryPoint",
    r"^_?_?TypeMatch", r"^_?_?CxxThrowException", r"^_?_?vcrt", r"^_?_?local_stdio",
]
_RE_RUNTIME = re.compile("|".join(PADROES_RUNTIME))
_RE_RUNTIME_DEM = re.compile(r"^(std::|`|__|_?Init_thread|Concurrency::)")


def nome_de_runtime(nome, demangled=None):
    if not nome:
        return False
    if _RE_RUNTIME.match(nome):
        return True
    if demangled and _RE_RUNTIME_DEM.match(demangled):
        return True
    return False


# ---------------------------------------------------------------------------
# Grafo de chamadas
# ---------------------------------------------------------------------------
def componentes_fortemente_conexos(grafo):
    """
    Tarjan iterativo. grafo: {no: iteravel_de_nos}. Retorna lista de componentes
    (listas de nos) em ordem topologica reversa: um componente aparece DEPOIS de
    todos os que ele chama, ou seja, folhas primeiro.
    """
    indice = {}
    baixo = {}
    na_pilha = set()
    pilha = []
    saida = []
    contador = 0
    nos = set(grafo)
    for v in list(grafo.values()):
        nos.update(v)
    for raiz in sorted(nos):
        if raiz in indice:
            continue
        trabalho = [(raiz, iter(sorted(grafo.get(raiz, ()))))]
        indice[raiz] = baixo[raiz] = contador
        contador += 1
        pilha.append(raiz)
        na_pilha.add(raiz)
        while trabalho:
            v, it = trabalho[-1]
            avancou = False
            for w in it:
                if w not in indice:
                    indice[w] = baixo[w] = contador
                    contador += 1
                    pilha.append(w)
                    na_pilha.add(w)
                    trabalho.append((w, iter(sorted(grafo.get(w, ())))))
                    avancou = True
                    break
                elif w in na_pilha:
                    baixo[v] = min(baixo[v], indice[w])
            if avancou:
                continue
            trabalho.pop()
            if trabalho:
                pai = trabalho[-1][0]
                baixo[pai] = min(baixo[pai], baixo[v])
            if baixo[v] == indice[v]:
                comp = []
                while True:
                    w = pilha.pop()
                    na_pilha.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                saida.append(sorted(comp))
    return saida


def ordem_folhas_primeiro(grafo):
    """
    grafo: {funcao: set(funcoes_chamadas)} (apenas as que importam).
    Retorna dict {no: {"nivel": n, "grupo": id, "recursivo": bool}} e a lista
    ordenada. Nivel 0 = nao chama nenhuma outra funcao do conjunto (folha).
    """
    comps = componentes_fortemente_conexos(grafo)
    comp_de = {}
    for i, c in enumerate(comps):
        for n in c:
            comp_de[n] = i
    nivel_comp = {}
    for i, c in enumerate(comps):   # ja esta em ordem folhas-primeiro
        nivel = 0
        for n in c:
            for w in grafo.get(n, ()):
                j = comp_de[w]
                if j != i:
                    nivel = max(nivel, nivel_comp[j] + 1)
        nivel_comp[i] = nivel
    info = {}
    for i, c in enumerate(comps):
        rec = len(c) > 1 or (c[0] in grafo.get(c[0], ()))
        for n in c:
            info[n] = {"nivel": nivel_comp[i], "grupo": i, "recursivo": rec}
    ordem = sorted(info, key=lambda n: (info[n]["nivel"], info[n]["grupo"], n))
    return info, ordem


def alcancaveis(grafo, raizes):
    visto = set()
    pilha = [r for r in raizes if r is not None]
    while pilha:
        n = pilha.pop()
        if n in visto:
            continue
        visto.add(n)
        pilha.extend(grafo.get(n, ()))
    return visto


# ---------------------------------------------------------------------------
# Tabelas numericas candidatas (coeficientes termodinamicos etc.)
# ---------------------------------------------------------------------------
def _double_plausivel(x):
    if x == 0.0:
        return True
    if math.isnan(x) or math.isinf(x):
        return False
    a = abs(x)
    return 1e-30 <= a <= 1e30


def _float_plausivel(x):
    if x == 0.0:
        return True
    if math.isnan(x) or math.isinf(x):
        return False
    a = abs(x)
    return 1e-20 <= a <= 1e20


def _fatiar_por_zeros(vals, max_zeros):
    """Divide `vals` em (inicio, lista) separando corridas de >= max_zeros zeros e
    descarta zeros nas pontas (preenchimento/alinhamento, nao dado)."""
    pecas = []
    atual, ini, zeros = [], 0, 0
    for k, v in enumerate(vals):
        if v == 0.0:
            zeros += 1
            atual.append(v)
            continue
        if zeros >= max_zeros:
            pecas.append((ini, atual[:len(atual) - zeros]))
            atual, ini = [], k
        zeros = 0
        if not atual:
            ini = k
        atual.append(v)
    if atual:
        pecas.append((ini, atual[:len(atual) - zeros] if zeros else atual))
    saida = []
    for ini, lst in pecas:
        k = 0
        while k < len(lst) and lst[k] == 0.0:
            k += 1
        lst = lst[k:]
        while lst and lst[-1] == 0.0:
            lst.pop()
        if lst:
            saida.append((ini + k, lst))
    return saida


def tabelas_candidatas(dados, base_ea, minimo=4, largura=8, max_zeros=4):
    """
    Procura sequencias alinhadas de doubles (largura=8) ou floats (largura=4)
    plausiveis dentro de `dados`. Corridas de zeros (>= max_zeros) separam tabelas e
    zeros nas pontas sao descartados. Exige pelo menos 2 valores nao nulos distintos
    e algum valor fracionario (descarta inteiros pequenos disfarcados de float).
    Retorna lista de dicts {ea, tipo, n, valores}.
    """
    fmt = "<d" if largura == 8 else "<f"
    ok = _double_plausivel if largura == 8 else _float_plausivel
    tipo = "double" if largura == 8 else "float"
    res = []
    n = len(dados) // largura
    i = 0
    while i < n:
        j = i
        vals = []
        while j < n:
            x = struct.unpack_from(fmt, dados, j * largura)[0]
            if not ok(x):
                break
            vals.append(x)
            j += 1
        for desloc, lst in _fatiar_por_zeros(vals, max_zeros):
            if len(lst) < minimo:
                continue
            nao_nulos = [v for v in lst if v != 0.0]
            fracionarios = [v for v in nao_nulos if v != math.floor(v)]
            if len(set(nao_nulos)) >= 2 and (fracionarios or len(set(nao_nulos)) > 2):
                res.append({"ea": base_ea + (i + desloc) * largura, "tipo": tipo,
                            "n": len(lst), "valores": lst})
        i = max(j, i) + 1
    return res


def literal_c_double(v):
    if v == 0.0:
        return "-0.0" if math.copysign(1.0, v) < 0 else "0.0"
    return repr(float(v))


# ---------------------------------------------------------------------------
# .def / cabecalhos
# ---------------------------------------------------------------------------
def escrever_def(caminho, nome_lib, exports):
    """
    exports: lista de dicts com ordinal, name, forwarder (opcional), data (bool).
    Mantem nomes e ordinais da DLL original.
    """
    linhas = ["; .def gerado automaticamente - mantem nomes e ordinais da DLL original",
              f'LIBRARY "{nome_lib}"', "EXPORTS"]
    for e in sorted(exports, key=lambda x: x["ordinal"]):
        nome = e.get("name") or ""
        ord_ = e["ordinal"]
        fwd = e.get("forwarder")
        extra = " DATA" if e.get("data") else ""
        if fwd:
            linhas.append(f"    {nome or f'Ordinal{ord_}'} = {fwd} @{ord_}" if nome
                          else f"    Ordinal{ord_} = {fwd} @{ord_} NONAME")
        elif nome:
            linhas.append(f"    {nome} @{ord_}{extra}")
        else:
            linhas.append(f"    Ordinal{ord_} @{ord_} NONAME{extra}")
    with open(caminho, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(linhas) + "\n")


def gravar_json(caminho, obj):
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)


def ler_json(caminho, padrao=None):
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return padrao


def gravar_csv(caminho, cabecalho, linhas, sep=";"):
    with open(caminho, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=sep)
        w.writerow(cabecalho)
        for l in linhas:
            w.writerow(l)


# ---------------------------------------------------------------------------
# Tipos C -> ctypes (usado pelo gerador de modelo do teste diferencial)
# ---------------------------------------------------------------------------
def tipo_c_para_ctypes(texto):
    """Devolve (tipo_base, e_ponteiro). Tipos desconhecidos viram int64."""
    t = (texto or "").replace("const", " ").replace("volatile", " ")
    ptr = "*" in t or "[" in t
    t = re.sub(r"[*\[\]\d]+", " ", t) if ptr else t
    for pal in ("__fastcall", "__stdcall", "__cdecl", "__thiscall", "__usercall",
                "__userpurge", "struct", "enum"):
        t = t.replace(pal, " ")
    t = " ".join(t.split()).lower()
    tab = [
        ("long double", "double"), ("double", "double"), ("float", "float"),
        ("unsigned __int64", "uint64"), ("__int64", "int64"), ("_qword", "uint64"),
        ("unsigned long long", "uint64"), ("long long", "int64"), ("size_t", "uint64"),
        ("unsigned __int16", "uint16"), ("__int16", "int16"), ("_word", "uint16"),
        ("unsigned short", "uint16"), ("short", "int16"),
        ("unsigned __int8", "uint8"), ("__int8", "int8"), ("_byte", "uint8"),
        ("unsigned char", "uint8"), ("char", "int8"), ("_bool", "int32"), ("bool", "int32"),
        ("unsigned int", "uint32"), ("_dword", "uint32"), ("unsigned long", "uint32"),
        ("int", "int32"), ("long", "int32"), ("void", "void"),
    ]
    for chave, val in tab:
        if t == chave or t.endswith(" " + chave) or t.startswith(chave):
            return val, ptr
    return ("void" if ptr else "int64"), ptr
