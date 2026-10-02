# -*- coding: utf-8 -*-
"""
teste_diferencial.py - compara DLL original x recompilada chamando as MESMAS funcoes
com as MESMAS entradas e comparando saidas com tolerancia numerica.

Cada DLL roda em um processo separado (worker) porque:
  * o Windows nao carrega duas DLLs com o mesmo nome de modulo no mesmo processo
    (original e recompilada normalmente se chamam igual);
  * runtime Fortran chama exit() em STOP/erro severo e Access Violation derruba o
    processo: um crash vira um resultado "crash" no relatorio, nao o fim do teste.

Uso:
  python teste_diferencial.py modelo EXPORTS_PROTOTYPES.json -o casos.json
        gera um modelo de casos a partir dos prototipos que o IDA inferiu
  python teste_diferencial.py listar original.dll [recompilada.dll]
        lista exports (e os que existem so em um dos lados)
  python teste_diferencial.py executar casos.json [--original X.dll] [--recompilada Y.dll]
        [--funcao NOME ...] [--dll-dir PASTA ...] [--saida relatorio] [--timeout 120]

Formato de casos.json (resumo; ver README.txt):
{
  "original": "orig\\\\ZE.dll", "recompilada": "novo\\\\ZE.dll",
  "convencao": "cdecl",                       # ou "stdcall" (so afeta x86)
  "tolerancia": {"rtol": 1e-9, "atol": 1e-12},
  "funcoes": [{
     "nome": "MOD_mp_FUNC_", "retorno": "void",
     "args": [{"nome":"T","tipo":"double","modo":"ref","dir":"in"},
              {"nome":"res","tipo":"double","modo":"ref","dir":"out","n":5},
              {"nome":"nome","tipo":"char","modo":"ref","n":32,"dir":"in"}],
     "len_oculto": false,
     "casos": [{"T": 300.0, "nome": "METANO"}],
     "fuzz": {"n": 100, "seed": 1, "faixas": {"T": [200, 1500]}, "escala": {"P": "log"},
              "normalizar": ["x"]}
  }]
}
modo: "val" (por valor) | "ref" (ponteiro; padrao Fortran). dir: in | out | inout.
tipos: int8 uint8 int16 uint16 int32 uint32 int64 uint64 float double logical char
"""
import argparse
import csv
import ctypes
import json
import math
import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402

CT = {
    "int8": ctypes.c_int8, "uint8": ctypes.c_uint8, "int16": ctypes.c_int16,
    "uint16": ctypes.c_uint16, "int32": ctypes.c_int32, "uint32": ctypes.c_uint32,
    "int64": ctypes.c_int64, "uint64": ctypes.c_uint64, "float": ctypes.c_float,
    "double": ctypes.c_double, "logical": ctypes.c_int32, "bool": ctypes.c_int32,
    "char": ctypes.c_char,
}
FLOATS = {"float", "double"}


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------
def maquina_pe(caminho):
    try:
        with open(caminho, "rb") as f:
            cab = f.read(0x400)
        if cab[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", cab, 0x3C)[0]
        return {0x14C: 32, 0x8664: 64, 0xAA64: 64}.get(struct.unpack_from("<H", cab, pe + 4)[0])
    except Exception:
        return None


def carregar_dll(caminho, convencao="cdecl", dll_dirs=()):
    caminho = os.path.abspath(caminho)
    if os.name == "nt":
        for d in [os.path.dirname(caminho), *dll_dirs]:
            if os.path.isdir(d):
                try:
                    os.add_dll_directory(d)
                except Exception:
                    pass
                os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
        return (ctypes.WinDLL if convencao == "stdcall" else ctypes.CDLL)(caminho)
    return ctypes.CDLL(caminho)


# ---------------------------------------------------------------------------
# Execucao de uma chamada (dentro do worker)
# ---------------------------------------------------------------------------
def _ct(tipo):
    if tipo not in CT:
        raise ValueError(f"tipo desconhecido: {tipo}")
    return CT[tipo]


def chamar(dll, spec, valores, hidden_t):
    """Executa uma chamada e devolve {'ret':..., 'out':{nome:[...]}}."""
    fn = getattr(dll, spec["nome"])
    argtypes, args, saidas, ocultos = [], [], {}, []
    for a in spec.get("args", []):
        t, n, modo = a["tipo"], int(a.get("n", 1)), a.get("modo", "ref")
        v = valores.get(a["nome"], a.get("padrao", 0))
        if t == "char":
            pad = b" " if a.get("pad", "space") == "space" else b"\0"
            b = (v if isinstance(v, bytes) else str(v).encode("latin-1", "replace"))[:n].ljust(n, pad)
            buf = ctypes.create_string_buffer(b, n)
            argtypes.append(ctypes.c_char_p)
            args.append(ctypes.cast(buf, ctypes.c_char_p))
            ocultos.append(n)
            saidas[a["nome"]] = (a, buf)
        elif modo == "val":
            argtypes.append(_ct(t))
            args.append(v)
        else:
            vals = list(v) if isinstance(v, (list, tuple)) else [v]
            vals = (vals + [a.get("padrao", 0)] * n)[:n]
            buf = (_ct(t) * n)(*vals)
            argtypes.append(ctypes.POINTER(_ct(t)))
            args.append(buf)
            saidas[a["nome"]] = (a, buf)
    if spec.get("len_oculto"):
        argtypes += [hidden_t] * len(ocultos)
        args += list(ocultos)
    fn.argtypes = argtypes
    ret = spec.get("retorno", "void")
    fn.restype = None if ret == "void" else _ct(ret)
    r = fn(*args)
    out = {}
    for nome, (a, buf) in saidas.items():
        if a.get("dir", "inout") == "in":
            continue
        if a["tipo"] == "char":
            out[nome] = [buf.raw.decode("latin-1").rstrip(" \0")]
        else:
            out[nome] = list(buf)
    return {"ret": r, "out": out}


def modo_worker(args):
    spec_all = json.load(open(args.worker_spec, encoding="utf-8"))
    spec = [f for f in spec_all["funcoes"] if f["nome"] == args.funcao][0]
    casos = json.load(open(args.worker_casos, encoding="utf-8"))
    conv = spec_all.get("convencao", "cdecl")
    dll = carregar_dll(args.worker, conv, args.dll_dir or [])
    hidden_t = ctypes.c_int64 if struct.calcsize("P") == 8 else ctypes.c_int32
    for c in casos[args.desde:]:
        print(json.dumps({"ev": "inicio", "id": c["id"]}), flush=True)
        try:
            r = chamar(dll, spec, c["valores"], hidden_t)
            print(json.dumps({"ev": "ok", "id": c["id"], **r}, default=str), flush=True)
        except OSError as e:     # access violation capturada pelo ctypes
            print(json.dumps({"ev": "erro", "id": c["id"], "erro": str(e)}), flush=True)
        except Exception as e:
            print(json.dumps({"ev": "erro", "id": c["id"], "erro": f"{type(e).__name__}: {e}"}), flush=True)
    return 0


# ---------------------------------------------------------------------------
# Geracao de casos
# ---------------------------------------------------------------------------
def _amostra(rng, a, faixa, escala):
    t = a["tipo"]
    lo, hi = faixa
    if t in FLOATS:
        if escala == "log" and lo > 0:
            return math.exp(rng.uniform(math.log(lo), math.log(hi)))
        return rng.uniform(lo, hi)
    return rng.randint(int(lo), int(hi))


def expandir_casos(spec):
    casos = []
    argd = {a["nome"]: a for a in spec.get("args", [])}
    for c in spec.get("casos", []):
        casos.append(dict(c))
    fz = spec.get("fuzz")
    if fz:
        rng = random.Random(fz.get("seed", 1))
        for _ in range(int(fz.get("n", 0))):
            c = {}
            for nome, faixa in fz.get("faixas", {}).items():
                a = argd[nome]
                esc = fz.get("escala", {}).get(nome, "linear")
                n = int(a.get("n", 1))
                c[nome] = _amostra(rng, a, faixa, esc) if n == 1 else [_amostra(rng, a, faixa, esc) for _ in range(n)]
            for nome in fz.get("normalizar", []):
                if isinstance(c.get(nome), list):
                    s = sum(c[nome]) or 1.0
                    c[nome] = [v / s for v in c[nome]]
            casos.append(c)
    return [{"id": i, "valores": c} for i, c in enumerate(casos)]


# ---------------------------------------------------------------------------
# Comparacao
# ---------------------------------------------------------------------------
def _ordenado(x):
    b = struct.unpack("<q", struct.pack("<d", x))[0]
    return b if b >= 0 else -(b & 0x7FFFFFFFFFFFFFFF)


def ulps(a, b):
    try:
        return abs(_ordenado(a) - _ordenado(b))
    except Exception:
        return None


def comparar_escalar(a, b, tol, e_float):
    """-> (ok, abs_err, rel_err, ulps)"""
    if isinstance(a, str) or isinstance(b, str):
        return a == b, None, None, None
    if e_float or isinstance(a, float) or isinstance(b, float):
        a, b = float(a), float(b)
        if math.isnan(a) and math.isnan(b):
            return True, 0.0, 0.0, 0
        if math.isnan(a) or math.isnan(b):
            return False, math.nan, math.nan, None
        if math.isinf(a) or math.isinf(b):
            return a == b, 0.0 if a == b else math.inf, 0.0 if a == b else math.inf, None
        d = abs(a - b)
        rel = d / max(abs(a), abs(b)) if max(abs(a), abs(b)) > 0 else 0.0
        ok = math.isclose(a, b, rel_tol=tol["rtol"], abs_tol=tol["atol"])
        if not ok and tol.get("ulps") is not None:
            u = ulps(a, b)
            ok = u is not None and u <= tol["ulps"]
        return ok, d, rel, ulps(a, b)
    return a == b, abs(a - b), None, None


def comparar_resultados(spec, ro, rr, tol):
    """Devolve lista de divergencias/linhas de comparacao [(campo, orig, recomp, ok, abs, rel, ulps)]."""
    linhas = []
    ret_t = spec.get("retorno", "void")
    if ret_t != "void":
        ok, d, r, u = comparar_escalar(ro["ret"], rr["ret"], tol, ret_t in FLOATS)
        linhas.append(("retorno", ro["ret"], rr["ret"], ok, d, r, u))
    tipos = {a["nome"]: a["tipo"] for a in spec.get("args", [])}
    for nome in sorted(set(ro["out"]) | set(rr["out"])):
        vo, vr = ro["out"].get(nome, []), rr["out"].get(nome, [])
        for k in range(max(len(vo), len(vr))):
            a = vo[k] if k < len(vo) else None
            b = vr[k] if k < len(vr) else None
            campo = f"{nome}[{k}]" if max(len(vo), len(vr)) > 1 else nome
            if a is None or b is None:
                linhas.append((campo, a, b, False, None, None, None))
                continue
            ok, d, r, u = comparar_escalar(a, b, tol, tipos.get(nome) in FLOATS)
            linhas.append((campo, a, b, ok, d, r, u))
    return linhas


# ---------------------------------------------------------------------------
# Orquestracao dos workers
# ---------------------------------------------------------------------------
def rodar_worker(dll, spec_path, casos_path, funcao, n_casos, dll_dirs, timeout):
    """Executa todos os casos numa DLL; sobrevive a crashes reiniciando apos o caso que falhou."""
    resultados = {}
    desde = 0
    while desde < n_casos:
        cmd = [sys.executable, os.path.abspath(__file__), "--worker", dll, "--worker-spec", spec_path,
               "--worker-casos", casos_path, "--funcao", funcao, "--desde", str(desde)]
        for d in dll_dirs:
            cmd += ["--dll-dir", d]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out, err = p.communicate(timeout=timeout)
            motivo = None
        except subprocess.TimeoutExpired as e:
            p.kill()
            out2, err = p.communicate()
            out = (e.output or "") if isinstance(e.output, str) else (e.output or b"").decode("utf-8", "replace")
            out += out2 or ""
            motivo = f"timeout ({timeout}s)"
        ultimo_inicio, concluido = None, set()
        for linha in out.splitlines():
            try:
                ev = json.loads(linha)
            except Exception:
                continue
            if ev["ev"] == "inicio":
                ultimo_inicio = ev["id"]
            else:
                resultados[ev["id"]] = ev
                concluido.add(ev["id"])
        if ultimo_inicio is not None and ultimo_inicio not in concluido:
            resultados[ultimo_inicio] = {"ev": "crash", "id": ultimo_inicio,
                                         "erro": motivo or f"processo terminou (rc={p.returncode}) {err.strip()[-200:]}"}
            desde = ultimo_inicio + 1
        elif p.returncode not in (0, None) and not concluido and ultimo_inicio is None:
            resultados[desde] = {"ev": "crash", "id": desde, "erro": f"worker falhou (rc={p.returncode}): {err.strip()[-300:]}"}
            return resultados, err.strip()[-300:]
        else:
            break
    return resultados, ""


def executar(args):
    spec = json.load(open(args.casos, encoding="utf-8"))
    orig = args.original or spec.get("original")
    novo = args.recompilada or spec.get("recompilada")
    if not orig or not novo:
        print("Informe original e recompilada (no JSON ou por --original/--recompilada).")
        return 2
    for caminho in (orig, novo):
        if not os.path.exists(caminho):
            print("Nao encontrei:", caminho)
            return 2
    mo, mn, mp = maquina_pe(orig), maquina_pe(novo), struct.calcsize("P") * 8
    for nome, m in (("original", mo), ("recompilada", mn)):
        if m and m != mp and os.name == "nt":
            print(f"ERRO: {nome} e {m}-bit mas este Python e {mp}-bit. Use um Python {m}-bit.")
            return 2
    tol = {"rtol": 1e-9, "atol": 1e-12, "ulps": None, **spec.get("tolerancia", {})}
    dll_dirs = list(args.dll_dir or []) + list(spec.get("dll_dirs", []))
    funcoes = [f for f in spec["funcoes"] if not args.funcao or f["nome"] in args.funcao]
    linhas_csv, resumo = [], []
    tmp = tempfile.mkdtemp(prefix="difftest_")
    spec_path = os.path.join(tmp, "spec.json")
    json.dump(spec, open(spec_path, "w", encoding="utf-8"))
    for f in funcoes:
        casos = expandir_casos(f)
        if not casos:
            print(f"[{f['nome']}] sem casos (use 'casos' ou 'fuzz')")
            continue
        casos_path = os.path.join(tmp, f["nome"] + ".casos.json")
        json.dump(casos, open(casos_path, "w", encoding="utf-8"))
        ftol = {**tol, **f.get("tolerancia", {})}
        ro, eo = rodar_worker(orig, spec_path, casos_path, f["nome"], len(casos), dll_dirs, args.timeout)
        rr, er = rodar_worker(novo, spec_path, casos_path, f["nome"], len(casos), dll_dirs, args.timeout)
        ok_n = bad_n = 0
        max_rel = 0.0
        for c in casos:
            i = c["id"]
            a, b = ro.get(i), rr.get(i)
            if not a or not b:
                status, det = "sem_resultado", [("-", None, None, False, None, None, None)]
            elif a["ev"] != "ok" or b["ev"] != "ok":
                if a["ev"] == b["ev"]:
                    status, det = "ambos_" + a["ev"], []
                else:
                    status = f"orig_{a['ev']}_recomp_{b['ev']}"
                    det = [("evento", a.get("erro") or a["ev"], b.get("erro") or b["ev"], False, None, None, None)]
            else:
                det = comparar_resultados(f, a, b, ftol)
                status = "ok" if all(d[3] for d in det) else "divergente"
            if status in ("ok", "ambos_erro", "ambos_crash"):
                ok_n += 1
            else:
                bad_n += 1
            for campo, va, vb, ok, d, r, u in det:
                if r is not None and not math.isnan(r):
                    max_rel = max(max_rel, r)
                if not ok or args.detalhado:
                    linhas_csv.append([f["nome"], i, status, campo, va, vb, d, r, u,
                                       json.dumps(c["valores"], ensure_ascii=False)[:300]])
            if not det and status != "ok":
                linhas_csv.append([f["nome"], i, status, "", "", "", "", "", "",
                                   json.dumps(c["valores"], ensure_ascii=False)[:300]])
        resumo.append({"funcao": f["nome"], "casos": len(casos), "ok": ok_n, "falhas": bad_n,
                       "max_erro_relativo": max_rel})
        print(f"[{'OK ' if bad_n == 0 else 'FALHA'}] {f['nome']}: {ok_n}/{len(casos)} casos; max erro relativo = {max_rel:.3e}")
    base = args.saida or "relatorio_diferencial"
    with open(base + ".csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["funcao", "caso", "status", "campo", "original", "recompilada", "erro_abs", "erro_rel", "ulps", "entradas"])
        w.writerows(linhas_csv)
    ac.gravar_json(base + ".json", {"tolerancia": tol, "resumo": resumo})
    total_bad = sum(r["falhas"] for r in resumo)
    print(f"\nRelatorio: {base}.csv / {base}.json   -> {'TUDO IGUAL' if total_bad == 0 else str(total_bad) + ' caso(s) divergente(s)'}")
    return 0 if total_bad == 0 else 1


# ---------------------------------------------------------------------------
# Modelo a partir dos prototipos do IDA + listar exports
# ---------------------------------------------------------------------------
def gerar_modelo(exports_json, saida, original="", recompilada=""):
    exps = json.load(open(exports_json, encoding="utf-8"))
    funcoes = []
    for e in exps:
        if e.get("tipo") != "funcao" or not e.get("proto"):
            continue
        p = e["proto"]
        args = []
        for k, a in enumerate(p.get("args") or []):
            base, ptr = ac.tipo_c_para_ctypes(a.get("tipo", ""))
            if base == "void":
                base = "double"
            args.append({"nome": a.get("nome") or f"a{k + 1}", "tipo": base,
                         "modo": "ref" if ptr else "val", "dir": "inout" if ptr else "in", "n": 1,
                         "_tipo_ida": a.get("tipo")})
        rb, rptr = ac.tipo_c_para_ctypes(p.get("ret") or "void")
        funcoes.append({
            "nome": e.get("name") or e.get("c_name"),
            "retorno": "void" if rb == "void" and not rptr else ("int64" if rptr else rb),
            "args": args,
            "len_oculto": False,
            "casos": [{a["nome"]: (1.0 if a["tipo"] in FLOATS else 1) for a in args}],
            "_proto_ida": p.get("decl"),
            "_aviso": "Prototipo inferido pelo IDA: confira tipos, n (tamanho de arrays) e dir (in/out).",
        })
    modelo = {"original": original, "recompilada": recompilada, "convencao": "cdecl",
              "tolerancia": {"rtol": 1e-9, "atol": 1e-12}, "dll_dirs": [], "funcoes": funcoes}
    ac.gravar_json(saida, modelo)
    return len(funcoes)


def listar(args):
    def nomes(dll):
        try:
            import pefile
        except ImportError:
            print("pefile nao instalado")
            return set()
        pe = pefile.PE(dll, fast_load=False)
        s = {x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name} if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else set()
        pe.close()
        return s
    a = nomes(args.dlls[0])
    print(f"{args.dlls[0]}: {len(a)} exports")
    if len(args.dlls) > 1:
        b = nomes(args.dlls[1])
        print(f"{args.dlls[1]}: {len(b)} exports")
        print("So na original   :", sorted(a - b) or "-")
        print("So na recompilada:", sorted(b - a) or "-")
    else:
        print("\n".join(sorted(a)))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--worker")
    ap.add_argument("--worker-spec")
    ap.add_argument("--worker-casos")
    ap.add_argument("--funcao", action="append")
    ap.add_argument("--desde", type=int, default=0)
    ap.add_argument("--dll-dir", action="append")
    sub = ap.add_subparsers(dest="cmd")
    m = sub.add_parser("modelo")
    m.add_argument("exports_json")
    m.add_argument("-o", "--saida", default="casos_teste.json")
    m.add_argument("--original", default="")
    m.add_argument("--recompilada", default="")
    li = sub.add_parser("listar")
    li.add_argument("dlls", nargs="+")
    ex = sub.add_parser("executar")
    ex.add_argument("casos")
    ex.add_argument("--original")
    ex.add_argument("--recompilada")
    ex.add_argument("--saida")
    ex.add_argument("--timeout", type=int, default=120)
    ex.add_argument("--detalhado", action="store_true", help="grava tambem as linhas que passaram")
    ex.add_argument("--funcao", action="append", dest="funcao")
    ex.add_argument("--dll-dir", action="append", dest="dll_dir")
    args = ap.parse_args()
    if args.worker:
        args.funcao = args.funcao[0]
        return modo_worker(args)
    if args.cmd == "modelo":
        n = gerar_modelo(args.exports_json, args.saida, args.original, args.recompilada)
        print(f"{n} funcao(oes) no modelo: {args.saida}")
        return 0
    if args.cmd == "listar":
        return listar(args)
    if args.cmd == "executar":
        return executar(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
