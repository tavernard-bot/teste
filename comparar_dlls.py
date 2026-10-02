# -*- coding: utf-8 -*-
"""
comparar_dlls.py - reanalisa a DLL RECOMPILADA com o mesmo pipeline e compara com a original.

Uso:
  python comparar_dlls.py PASTA_ORIGINAL RECOMPILADA.dll [--ida ida.exe] [--timeout 3600] [--sem-ida]

  PASTA_ORIGINAL : pasta de resultado da DLL original (ex.: D:\\DLLs\\ze\\_REVERSE\\NOME)
  RECOMPILADA    : a DLL que voce compilou (ex.: ...\\projeto\\build\\NOME.dll)
  --sem-ida      : compara so o nivel PE (exports, imports, secoes); nao roda o IDA

Resultado em PASTA_ORIGINAL\\comparacao\\ :
  comparacao.md / comparacao.json        veredito por criterio
  funcoes_tamanho.csv                    tamanho (bytes) das funcoes homonimas nas duas DLLs
  (analise completa da recompilada em PASTA_ORIGINAL\\comparacao\\recompilada\\NOME\\)

O que e comparado: exports (nomes e ordinais), imports (DLLs e funcoes), tamanho das secoes,
numero de funcoes (total/usuario), tamanho das funcoes exportadas, chamadas externas das
exportadas. Para comparacao estrutural fina use o BinDiff (IDA 9.1) nos dois .i64 listados.
Para igualdade NUMERICA use teste_diferencial.py (e o que realmente importa).
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402
import classificar_dll  # noqa: E402


def _exports_map(lista):
    return {(e.get("name") or f"#{e['ordinal']}"): e["ordinal"] for e in lista}


def _imports_set(imps):
    s = set()
    for e in imps or []:
        for f in e["functions"]:
            s.add(f"{e['dll'].lower()}!{f['name'] or '#' + str(f['ordinal'])}")
    return s


def _funcs_por_nome(base):
    fj = ac.ler_json(os.path.join(base, "functions.json"), []) or []
    return {f["name_original"]: f for f in fj}


def comparar(orig, recomp, ida=None, timeout=3600, usar_ida=True):
    orig = os.path.abspath(orig)
    nome = os.path.basename(orig.rstrip("\\/"))
    saida = os.path.join(orig, "comparacao")
    pasta_rec = os.path.join(saida, "recompilada")
    os.makedirs(pasta_rec, exist_ok=True)
    rec_dir = os.path.join(pasta_rec, nome)
    veredito = {}

    # --- 1) reanalisa a recompilada com o MESMO pipeline ---
    if usar_ida and ida:
        import orquestrar
        entrada = os.path.join(saida, "entrada")
        os.makedirs(entrada, exist_ok=True)
        shutil.copyfile(recomp, os.path.join(entrada, nome + ".dll"))
        orquestrar.main(["--ida", ida, "--dlls", entrada, "--out", pasta_rec, "--timeout", str(timeout), "--force"])
    else:
        for velho in ("analysis_summary.json", "functions.json", "callgraph.json"):   # evita comparar com sobras
            try:
                os.remove(os.path.join(rec_dir, velho))
            except OSError:
                pass
        classificar_dll.analisar(recomp, rec_dir)

    # --- 2) PE: exports / imports / secoes ---
    eo = _exports_map(ac.ler_json(os.path.join(orig, "exports_pe.json"), []) or [])
    er = _exports_map(ac.ler_json(os.path.join(rec_dir, "exports_pe.json"), []) or [])
    faltam = sorted(set(eo) - set(er))
    sobram = sorted(set(er) - set(eo))
    ordem_dif = sorted(n for n in set(eo) & set(er) if eo[n] != er[n])
    veredito["exports"] = {"ok": not (faltam or sobram or ordem_dif), "original": len(eo), "recompilada": len(er),
                           "faltam_na_recompilada": faltam, "a_mais_na_recompilada": sobram,
                           "ordinal_diferente": [(n, eo[n], er[n]) for n in ordem_dif]}
    io = _imports_set(ac.ler_json(os.path.join(orig, "imports_pe.json"), []))
    ir = _imports_set(ac.ler_json(os.path.join(rec_dir, "imports_pe.json"), []))
    dll_o = {x.split("!")[0] for x in io}
    dll_r = {x.split("!")[0] for x in ir}
    veredito["imports"] = {"ok": io <= ir or not (io - ir), "dlls_so_na_original": sorted(dll_o - dll_r),
                           "dlls_so_na_recompilada": sorted(dll_r - dll_o),
                           "funcoes_so_na_original": sorted(io - ir)[:200],
                           "funcoes_so_na_recompilada": sorted(ir - io)[:200]}
    co = ac.ler_json(os.path.join(orig, "compiler_info.json"), {}) or {}
    cr = ac.ler_json(os.path.join(rec_dir, "compiler_info.json"), {}) or {}
    so = {s["nome"]: s for s in co.get("secoes", [])}
    sr = {s["nome"]: s for s in cr.get("secoes", [])}
    tab_sec = []
    for n in sorted(set(so) | set(sr)):
        a, b = (so.get(n) or {}).get("vsize"), (sr.get(n) or {}).get("vsize")
        tab_sec.append({"secao": n, "original": a, "recompilada": b,
                        "delta_pct": round(100.0 * (b - a) / a, 1) if a and b else None})
    veredito["secoes"] = tab_sec
    veredito["linker"] = {"original": co.get("toolset_pelo_linker"), "recompilada": cr.get("toolset_pelo_linker")}
    veredito["crt"] = {"original": [c["runtime"] for c in co.get("crt", [])],
                       "recompilada": [c["runtime"] for c in cr.get("crt", [])]}

    # --- 3) IDA: funcoes ---
    so_ = ac.ler_json(os.path.join(orig, "analysis_summary.json"), None)
    sr_ = ac.ler_json(os.path.join(rec_dir, "analysis_summary.json"), None)
    linhas = []
    if so_ and sr_:
        fo, fr = _funcs_por_nome(orig), _funcs_por_nome(rec_dir)
        veredito["funcoes"] = {
            "total": {"original": so_["funcoes"], "recompilada": sr_["funcoes"]},
            "usuario": {"original": so_["funcoes_usuario"], "recompilada": sr_["funcoes_usuario"]},
            "falhas_decompilador": {"original": so_["falhas_decompilador"], "recompilada": sr_["falhas_decompilador"]},
            "isa": {"original": so_.get("isa_contagem"), "recompilada": sr_.get("isa_contagem")},
            "arch_sugerida": {"original": so_.get("flag_arch_sugerida"), "recompilada": sr_.get("flag_arch_sugerida")},
        }
        tam_o = sum(f["size"] for f in fo.values() if f["kind"] in ("user", "init", "orphan"))
        tam_r = sum(f["size"] for f in fr.values() if f["kind"] in ("user", "init", "orphan"))
        veredito["funcoes"]["codigo_usuario_bytes"] = {"original": tam_o, "recompilada": tam_r,
                                                      "delta_pct": round(100.0 * (tam_r - tam_o) / tam_o, 1) if tam_o else None}
        exp_o = {n for n, f in fo.items() if f.get("exported")}
        for n in sorted(set(fo) & set(fr)):
            a, b = fo[n]["size"], fr[n]["size"]
            linhas.append([n, "exportada" if n in exp_o else "", fo[n]["kind"], a, b, b - a,
                           round(100.0 * (b - a) / a, 1) if a else ""])
        grandes = [l for l in linhas if l[1] and isinstance(l[6], float) and abs(l[6]) > 50]
        veredito["funcoes"]["exportadas_com_tamanho_muito_diferente"] = [l[0] for l in grandes]
        # chamadas externas das exportadas (mesma lista de APIs/runtime?)
        cg_o = {n["name_original"]: n for n in (ac.ler_json(os.path.join(orig, "callgraph.json"), {}) or {}).get("nos", [])}
        cg_r = {n["name_original"]: n for n in (ac.ler_json(os.path.join(rec_dir, "callgraph.json"), {}) or {}).get("nos", [])}
        dif_ext = {}
        for n in exp_o & set(cg_r):
            a, b = set(cg_o[n]["externs"]), set(cg_r[n]["externs"])
            if a != b:
                dif_ext[n] = {"so_original": sorted(a - b), "so_recompilada": sorted(b - a)}
        veredito["funcoes"]["externos_diferentes_nas_exportadas"] = dif_ext
        veredito["bindiff"] = {"original_i64": _achar_i64(orig), "recompilada_i64": _achar_i64(rec_dir)}
    else:
        veredito["funcoes"] = {"aviso": "analysis_summary.json ausente em uma das pastas (IDA nao rodou?)"}

    # --- saidas ---
    ac.gravar_json(os.path.join(saida, "comparacao.json"), veredito)
    ac.gravar_csv(os.path.join(saida, "funcoes_tamanho.csv"),
                  ["funcao", "exportada", "tipo", "bytes_original", "bytes_recompilada", "delta", "delta_pct"], linhas)
    md = [f"# Comparacao original x recompilada - {nome}", ""]
    e = veredito["exports"]
    md += ["## Exports", f"- Original: {e['original']}  |  Recompilada: {e['recompilada']}  ->  **{'OK' if e['ok'] else 'DIFERENTE'}**"]
    for k, t in (("faltam_na_recompilada", "Faltam"), ("a_mais_na_recompilada", "A mais"), ("ordinal_diferente", "Ordinal diferente")):
        if e[k]:
            md.append(f"- {t}: {', '.join(map(str, e[k][:50]))}")
    i = veredito["imports"]
    md += ["", "## Imports", f"- DLLs so na original: {i['dlls_so_na_original'] or '-'}",
           f"- DLLs so na recompilada: {i['dlls_so_na_recompilada'] or '-'}"]
    md += ["", "## Secoes (tamanho virtual)", "| secao | original | recompilada | delta |", "|---|---|---|---|"]
    md += [f"| {s['secao']} | {s['original']} | {s['recompilada']} | {s['delta_pct']}% |" for s in tab_sec]
    md += ["", f"Linker: {veredito['linker']}", f"CRT: {veredito['crt']}"]
    if "total" in veredito["funcoes"]:
        f = veredito["funcoes"]
        md += ["", "## Funcoes", f"- Total: {f['total']}", f"- Codigo do usuario: {f['usuario']}  bytes: {f['codigo_usuario_bytes']}",
               f"- Falhas do decompilador: {f['falhas_decompilador']}", f"- ISA: {f['isa']}",
               f"- Exportadas com tamanho muito diferente (>50%): {f['exportadas_com_tamanho_muito_diferente'] or '-'}",
               f"- Exportadas com chamadas externas diferentes: {list(f['externos_diferentes_nas_exportadas']) or '-'}",
               "", "## BinDiff", f"- {veredito['bindiff']['original_i64']}", f"- {veredito['bindiff']['recompilada_i64']}"]
    else:
        md += ["", "## Funcoes", veredito["funcoes"].get("aviso", "")]
    md += ["", "> Igualdade de bytes raramente acontece. O criterio decisivo e numerico: teste_diferencial.py."]
    with open(os.path.join(saida, "comparacao.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    return veredito, saida


def _achar_i64(pasta):
    for ext in (".i64", ".idb"):
        for f in os.listdir(pasta):
            if f.lower().endswith(ext):
                return os.path.join(pasta, f)
    return "(banco do IDA nao encontrado)"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("original")
    ap.add_argument("recompilada")
    ap.add_argument("--ida")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--sem-ida", action="store_true")
    a = ap.parse_args()
    if not a.sem_ida and not a.ida:
        print("Informe --ida (caminho do ida.exe) ou use --sem-ida.")
        return 2
    v, saida = comparar(a.original, a.recompilada, a.ida, a.timeout, not a.sem_ida)
    print("Exports:", "OK" if v["exports"]["ok"] else "DIFERENTE", "| relatorio:", os.path.join(saida, "comparacao.md"))
    return 0 if v["exports"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
