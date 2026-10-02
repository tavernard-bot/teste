# -*- coding: utf-8 -*-
"""
dependencias_dlls.py - grafo de dependencias ENTRE as DLLs da pasta e ordem de build.

Fontes de aresta (A depende de B quando B esta na pasta analisada):
  * imports (normais e delay-load)           imports_pe.json
  * forwarders de export (A -> "B.func")     exports_pe.json
  * strings "*.dll" no binario (LoadLibrary) strings.txt   (so se o IDA ja rodou)

Saidas em <out>:  dependencias_dlls.json / .csv, ordem_build.txt, dependencias_externas.csv
Ordem de build: dependencias primeiro; ciclos aparecem agrupados.

Uso:  python dependencias_dlls.py PASTA_REVERSE
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402

SISTEMA = {
    "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "ntdll.dll", "msvcrt.dll", "ws2_32.dll", "comctl32.dll",
    "comdlg32.dll", "shlwapi.dll", "version.dll", "winmm.dll", "psapi.dll", "rpcrt4.dll",
    "bcrypt.dll", "crypt32.dll", "imm32.dll", "mscoree.dll", "ucrtbase.dll", "sechost.dll",
}
RUNTIME_TERCEIROS = re.compile(
    r"^(msvc[pr]\d+d?|vcruntime\d+(_\d)?d?|msvcp\d+(_\d)?|concrt\d+|vcomp\d+|libifcore\w*|libifport\w*|libmmd|"
    r"libirc|svml_disp\w*|libiomp5md|mkl_\w+|libgfortran[-\w.]*|libquadmath[-\w.]*|libgcc_s\w*[-\w.]*|"
    r"libstdc\+\+[-\w.]*|libwinpthread[-\w.]*|libgomp[-\w.]*)\.dll$", re.I)


def _stem(n):
    return os.path.splitext(n.lower())[0]


def classe_dll(nome):
    n = nome.lower()
    if n.startswith(("api-ms-", "ext-ms-")) or n in SISTEMA:
        return "sistema"
    if RUNTIME_TERCEIROS.match(n):
        return "runtime_terceiros"
    return "outra"


def construir(out_dir, nomes=None):
    """nomes: lista de pastas (nome da DLL) a considerar; padrao = subpastas com imports_pe.json."""
    pastas = nomes or sorted(d for d in os.listdir(out_dir)
                             if os.path.isfile(os.path.join(out_dir, d, "imports_pe.json")))
    existentes = {_stem(p): p for p in pastas}
    arestas = {}      # (a, b) -> set(motivos)
    externas = {}     # dll externa -> {classe, usadas_por:set}
    for p in pastas:
        base = os.path.join(out_dir, p)
        imps = ac.ler_json(os.path.join(base, "imports_pe.json"), []) or []
        for e in imps:
            alvo = _stem(e["dll"])
            motivo = "delay-load" if e.get("delay") else "import"
            if alvo in existentes and existentes[alvo] != p:
                arestas.setdefault((p, existentes[alvo]), set()).add(motivo)
            elif alvo not in existentes:
                x = externas.setdefault(e["dll"].lower(), {"classe": classe_dll(e["dll"]), "usadas_por": set()})
                x["usadas_por"].add(p)
        for ex in ac.ler_json(os.path.join(base, "exports_pe.json"), []) or []:
            f = ex.get("forwarder")
            if f and "." in f:
                alvo = _stem(f.split(".")[0])
                if alvo in existentes and existentes[alvo] != p:
                    arestas.setdefault((p, existentes[alvo]), set()).add("forwarder")
        sp = os.path.join(base, "strings.txt")
        if os.path.exists(sp):
            try:
                with open(sp, encoding="utf-8", errors="replace") as fh:
                    for linha in fh:
                        for m in re.finditer(r"([A-Za-z0-9_.\-]+)\.dll\b", linha, re.I):
                            alvo = m.group(1).lower()
                            if alvo in existentes and existentes[alvo] != p:
                                arestas.setdefault((p, existentes[alvo]), set()).add("string(LoadLibrary?)")
            except OSError:
                pass
    grafo = {p: set() for p in pastas}
    for (a, b) in arestas:
        grafo[a].add(b)
    comps = ac.componentes_fortemente_conexos(grafo)   # dependencias primeiro
    ordem = []
    for c in comps:
        ordem.append({"dlls": c, "ciclo": len(c) > 1 or (c[0] in grafo[c[0]])})
    return grafo, arestas, externas, ordem


def escrever(out_dir, nomes=None):
    grafo, arestas, externas, ordem = construir(out_dir, nomes)
    ac.gravar_json(os.path.join(out_dir, "dependencias_dlls.json"), {
        "dependencias": {k: sorted(v) for k, v in grafo.items()},
        "motivos": {f"{a}->{b}": sorted(m) for (a, b), m in arestas.items()},
        "ordem_build": ordem,
        "externas": {k: {"classe": v["classe"], "usadas_por": sorted(v["usadas_por"])} for k, v in externas.items()},
    })
    ac.gravar_csv(os.path.join(out_dir, "dependencias_dlls.csv"), ["dll", "depende_de", "motivo"],
                  [[a, b, ",".join(sorted(m))] for (a, b), m in sorted(arestas.items())])
    ac.gravar_csv(os.path.join(out_dir, "dependencias_externas.csv"), ["dll_externa", "classe", "usada_por"],
                  [[k, v["classe"], ";".join(sorted(v["usadas_por"]))] for k, v in sorted(externas.items())])
    L = ["ORDEM DE BUILD (recompile de cima para baixo; cada item so depende dos anteriores)", "=" * 70]
    for n, grp in enumerate(ordem, 1):
        marca = "  [CICLO: recompilar juntas / usar import lib intermediaria]" if grp["ciclo"] else ""
        L.append(f"{n:3d}. {', '.join(grp['dlls'])}{marca}")
    terc = sorted(k for k, v in externas.items() if v["classe"] == "runtime_terceiros")
    if terc:
        L += ["", "Runtimes de terceiros necessarios (instalar/redistribuir ao recompilar/testar):",
              *["  - " + t for t in terc]]
    with open(os.path.join(out_dir, "ordem_build.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return ordem


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    o = escrever(os.path.abspath(sys.argv[1]))
    print(f"{len(o)} grupo(s) na ordem de build -> ordem_build.txt")
