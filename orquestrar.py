# -*- coding: utf-8 -*-
"""
orquestrar.py - controla o lote inteiro (chamado por analisar_dlls.bat).

Para cada DLL da pasta:
  1. classifica o PE (classificar_dll.py): nativa | mista | gerenciada | invalida
  2. NATIVA  -> IDA/Hex-Rays (analisar_ida.py) com TIMEOUT (mata a arvore de processos)
     MISTA   -> IDA para a parte nativa  +  dotPeek para a parte gerenciada
     GERENCIADA (IL-only) -> NAO vai para o IDA; vai para o dotPeek
  3. gera o esqueleto de recompilacao (gerar_projeto.py)
  4. grava ANALISE_CONCLUIDA.json (retomada: DLLs ja analisadas e sem alteracao sao puladas)
No fim: resumo.csv, dependencias/ordem de build entre as DLLs.
"""
import argparse
import concurrent.futures as cf
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402
import classificar_dll  # noqa: E402
import dependencias_dlls  # noqa: E402
import gerar_projeto  # noqa: E402

AQUI = os.path.dirname(os.path.abspath(__file__))
SKIP_STATUS = {"ok", "parcial", "gerenciada", "nao_pe"}       # nao refaz (sem --force)
FALHAS = {"erro", "timeout"}                                   # refaz, salvo --pular-falhas
COLUNAS = ["dll", "status", "tipo", "arquitetura", "classificacao", "compilador_sugerido", "toolset_linker",
           "exports", "funcoes", "funcoes_usuario", "funcoes_lib", "decompiladas", "falhas_decompilador",
           "tabelas_candidatas", "classes_rtti", "gerenciada_dotpeek", "segundos", "ida_rc", "observacao", "pasta"]
_trava = threading.Lock()


def log(msg, arq=None):
    with _trava:
        try:
            print(msg, flush=True)
        except UnicodeEncodeError:
            print(msg.encode("ascii", "replace").decode(), flush=True)
        if arq:
            with open(arq, "a", encoding="utf-8") as f:
                f.write(time.strftime("%H:%M:%S ") + msg + "\n")


# ---------------------------------------------------------------------------
def matar_arvore(p):
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
        else:
            p.kill()
    except Exception:
        pass


def comando_ida(cfg, work, dll_copia):
    ida = cfg.ida
    if not cfg.usar_gui:
        idat = os.path.join(os.path.dirname(ida), "idat.exe")
        if os.path.exists(idat):
            ida = idat
    script = os.path.join(AQUI, "analisar_ida.py")
    logf = os.path.join(work, "ida.log")
    if os.name == "nt":
        # string unica: o IDA espera -S"caminho" com aspas literais
        return f'"{ida}" -A -c -L"{logf}" -S"{script}" "{dll_copia}"'
    return [ida, "-A", "-c", f"-L{logf}", f"-S{script}", dll_copia]


def rodar_ida(cfg, work, dll_copia):
    env = dict(os.environ)
    inicio = time.time()
    env.update({
        "IDA_OUTPUT": work, "RECOVERY_SCRIPTS": AQUI, "PYTHONUTF8": "1",
        "IDA_SOFT_DEADLINE": str(inicio + cfg.timeout * 0.7),
        "IDA_DECOMPILE_LIB": "1" if cfg.decompile_lib else "0",
        "IDA_ASM_FULL": "0" if cfg.sem_asm else "1",
        "IDA_RENOMEAR": "0" if cfg.sem_renomear else "1",
    })
    for velho in ("analysis_summary.json", "ida_script_error.txt"):
        try:
            os.remove(os.path.join(work, velho))
        except OSError:
            pass
    p = subprocess.Popen(comando_ida(cfg, work, dll_copia), env=env, cwd=work,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        rc = p.wait(timeout=cfg.timeout)
        return rc, False, time.time() - inicio
    except subprocess.TimeoutExpired:
        matar_arvore(p)
        try:
            p.wait(timeout=30)
        except Exception:
            pass
        return None, True, time.time() - inicio


# ---------------------------------------------------------------------------
# Gerenciadas (dotPeek)
# ---------------------------------------------------------------------------
def achar_dotpeek(cfg):
    if cfg.dotpeek and os.path.exists(cfg.dotpeek):
        return cfg.dotpeek
    pads = []
    for base in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("ProgramFiles", ""),
                 os.environ.get("ProgramFiles(x86)", "")):
        if base:
            pads += [os.path.join(base, "JetBrains", "Installations", "dotPeek*", "dotPeek64.exe"),
                     os.path.join(base, "JetBrains", "dotPeek*", "bin", "dotPeek64.exe"),
                     os.path.join(base, "Programs", "dotPeek*", "bin", "dotPeek64.exe")]
    for pad in pads:
        achados = sorted(glob.glob(pad))
        if achados:
            return achados[-1]
    return None


def preparar_gerenciada(cfg, dll, nome, work):
    """Copia para _GERENCIADAS\\ e, se houver CLI configurada, decompila. Retorna texto de status."""
    pasta = os.path.join(cfg.out, "_GERENCIADAS")
    os.makedirs(pasta, exist_ok=True)
    destino = os.path.join(pasta, os.path.basename(dll))
    shutil.copyfile(dll, destino)
    saida = os.path.join(pasta, "fonte_cs", nome)
    texto = "preparada em _GERENCIADAS (abrir no dotPeek: Export to Project)"
    for nome_cli, modelo in (("dotpeek-cmd", cfg.dotpeek_cmd), ("ilspycmd", cfg.ilspy_cmd)):
        if not modelo:
            continue
        os.makedirs(saida, exist_ok=True)
        cmd = modelo.replace("{dll}", destino).replace("{out}", saida)
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=cfg.timeout)
            if r.returncode == 0:
                texto = f"decompilada via {nome_cli} em {saida}"
                break
            texto += f" | {nome_cli} falhou rc={r.returncode}: {(r.stderr or r.stdout)[-160:].strip()}"
        except Exception as e:
            texto += f" | {nome_cli} erro: {e}"
    return texto


def atualizar_bat_dotpeek(cfg):
    pasta = os.path.join(cfg.out, "_GERENCIADAS")
    if not os.path.isdir(pasta):
        return
    dlls = sorted(glob.glob(os.path.join(pasta, "*.dll")))
    if not dlls:
        return
    exe = achar_dotpeek(cfg) or "dotPeek64.exe"
    L = ["@echo off", "REM Abre todas as DLLs gerenciadas no dotPeek.",
         "REM No dotPeek: selecione as assemblies no Assembly Explorer > botao direito > Export to Project...",
         "REM (a exportacao e feita pela interface; o dotPeek nao tem CLI de exportacao documentada)"]
    for k in range(0, len(dlls), 15):
        L.append(f'start "" "{exe}" ' + " ".join(f'"{d}"' for d in dlls[k:k + 15]))
    with open(os.path.join(pasta, "abrir_no_dotpeek.bat"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\r\n".join(L) + "\r\n")


# ---------------------------------------------------------------------------
def deve_pular(cfg, work, sha):
    m = ac.ler_json(os.path.join(work, "ANALISE_CONCLUIDA.json"))
    if cfg.force or not m or m.get("sha256") != sha or m.get("versao_pipeline") != ac.VERSAO_PIPELINE:
        return None
    st = m.get("status")
    if st in SKIP_STATUS or (cfg.pular_falhas and st in FALHAS):
        return m
    return None


def processar(cfg, dll, nome, idx, total):
    t0 = time.time()
    work = os.path.join(cfg.out, nome)
    os.makedirs(work, exist_ok=True)
    arqlog = os.path.join(cfg.out, "orquestrador.log")
    tag = f"[{idx}/{total}] {os.path.basename(dll)}"
    try:
        sha = hashlib.sha256(open(dll, "rb").read()).hexdigest()
    except OSError as e:
        return {"dll": nome, "status": "erro", "observacao": f"nao consegui ler: {e}", "pasta": work}
    ant = deve_pular(cfg, work, sha)
    if ant:
        log(f"{tag}: PULADA (ja analisada: {ant['status']}). Use --force para refazer.", arqlog)
        ant["linha"]["observacao"] = ("(retomada) " + (ant["linha"].get("observacao") or "")).strip()
        return ant["linha"]

    log(f"{tag}: classificando...", arqlog)
    res = classificar_dll.analisar(dll, work)
    linha = {c: "" for c in COLUNAS}
    linha.update({"dll": nome, "pasta": work})
    if res.get("erro"):
        linha.update({"status": "nao_pe", "tipo": "invalida", "observacao": res["erro"]})
        return _concluir(cfg, work, sha, linha, t0)
    linha.update({
        "tipo": res["tipo"], "arquitetura": res["arquitetura"], "classificacao": res["classificacao"],
        "compilador_sugerido": res.get("compilador", ""), "toolset_linker": res.get("toolset", ""),
        "exports": res["n_exports"], "observacao": res.get("observacao", ""),
    })
    log(f"{tag}: {res['classificacao']} [{res['tipo']}] {res['arquitetura']} | {res.get('compilador', '')}", arqlog)

    obs = []
    if res["tipo"] in ("gerenciada", "mista"):
        txt = preparar_gerenciada(cfg, dll, nome, work)
        linha["gerenciada_dotpeek"] = txt
        obs.append(txt)
        log(f"{tag}: parte gerenciada -> {txt}", arqlog)

    if res["tipo"] == "gerenciada":
        linha["status"] = "gerenciada"
        linha["observacao"] = " | ".join(x for x in [linha["observacao"], "NAO enviada ao IDA (IL-only): usar dotPeek"] if x)
        return _concluir(cfg, work, sha, linha, t0)

    # --- nativa ou mista: IDA ---
    copia = os.path.join(work, os.path.basename(dll))
    shutil.copyfile(dll, copia)
    log(f"{tag}: IDA Pro (timeout {cfg.timeout}s)...", arqlog)
    rc, estourou, seg = rodar_ida(cfg, work, copia)
    linha["ida_rc"] = "" if rc is None else rc
    resumo = ac.ler_json(os.path.join(work, "analysis_summary.json"))
    if estourou:
        linha["status"] = "timeout"
        obs.append(f"IDA excedeu {cfg.timeout}s e foi encerrado (saidas parciais mantidas)")
        srcs = len(glob.glob(os.path.join(work, "projeto", "src", "*.c")))
        linha["decompiladas"] = srcs
    elif resumo:
        linha["status"] = resumo["status"]
        for k_dst, k_src in (("funcoes", "funcoes"), ("funcoes_usuario", "funcoes_usuario"), ("funcoes_lib", "funcoes_lib"),
                             ("decompiladas", "decompiladas"), ("falhas_decompilador", "falhas_decompilador"),
                             ("tabelas_candidatas", "tabelas_candidatas"), ("classes_rtti", "classes_rtti")):
            linha[k_dst] = resumo.get(k_src, "")
        if resumo.get("puladas_prazo"):
            obs.append(f"{resumo['puladas_prazo']} funcao(oes) nao decompiladas por prazo")
        erros = [n for n, f in resumo.get("fases", {}).items() if f["status"] == "erro"]
        if erros:
            obs.append("fases com erro: " + ",".join(erros))
        if resumo.get("avisos"):
            obs += resumo["avisos"]
    else:
        linha["status"] = "erro"
        err = os.path.join(work, "ida_script_error.txt")
        obs.append(f"IDA rc={rc}; sem analysis_summary.json" + ("; ver ida_script_error.txt" if os.path.exists(err) else "; ver ida.log"))
    linha["segundos"] = round(seg, 1)

    # esqueleto de projeto (mesmo se parcial)
    try:
        gerar_projeto.gerar(work, os.path.dirname(cfg.ida), AQUI, cfg.python_exe)
    except Exception as e:
        obs.append(f"gerar_projeto falhou: {e}")
    linha["observacao"] = " | ".join(x for x in [linha["observacao"], *obs] if x)
    log(f"{tag}: {linha['status'].upper()}  funcoes={linha['funcoes']} decompiladas={linha['decompiladas']} "
        f"falhas={linha['falhas_decompilador']}  ({linha['segundos']}s)", arqlog)
    return _concluir(cfg, work, sha, linha, t0)


def _concluir(cfg, work, sha, linha, t0):
    if not linha.get("segundos"):
        linha["segundos"] = round(time.time() - t0, 1)
    ac.gravar_json(os.path.join(work, "ANALISE_CONCLUIDA.json"), {
        "sha256": sha, "versao_pipeline": ac.VERSAO_PIPELINE, "status": linha["status"],
        "data": time.strftime("%Y-%m-%d %H:%M:%S"), "linha": linha})
    with open(os.path.join(work, "ANALISE_CONCLUIDA.txt"), "w", encoding="utf-8") as f:
        f.write(f"DLL: {linha['dll']}\nStatus: {linha['status']}\nTipo: {linha['tipo']}\n"
                f"Pasta: {work}\nData: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    return linha


def gravar_resumo(cfg, linhas):
    with _trava:
        ordenado = sorted(linhas.values(), key=lambda l: l["dll"].lower())
        ac.gravar_csv(os.path.join(cfg.out, "resumo.csv"), COLUNAS,
                      [[l.get(c, "") for c in COLUNAS] for l in ordenado], sep=cfg.csv_sep)
        ac.gravar_json(os.path.join(cfg.out, "resumo.json"), ordenado)


def descobrir(cfg):
    exts = tuple("." + e.strip().lower().lstrip(".") for e in cfg.ext.split(","))
    achados = []
    if cfg.recursive:
        for raiz, dirs, arqs in os.walk(cfg.dlls):
            dirs[:] = [d for d in dirs if os.path.abspath(os.path.join(raiz, d)) != os.path.abspath(cfg.out)]
            achados += [os.path.join(raiz, a) for a in arqs if a.lower().endswith(exts)]
    else:
        achados = [os.path.join(cfg.dlls, a) for a in os.listdir(cfg.dlls) if a.lower().endswith(exts)]
    achados.sort(key=str.lower)
    if cfg.only:
        quer = {x.strip().lower() for x in cfg.only.split(",")}
        achados = [a for a in achados if os.path.splitext(os.path.basename(a))[0].lower() in quer
                   or os.path.basename(a).lower() in quer]
    usados, saida = {}, []
    for a in achados:
        n = os.path.splitext(os.path.basename(a))[0]
        if n.lower() in usados:
            n = f"{n}_{abs(hash(os.path.dirname(a))) % 0xFFFFFF:06x}"
        usados[n.lower()] = a
        saida.append((a, n))
    return saida


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ida", required=True, help="caminho do ida.exe")
    ap.add_argument("--dlls", required=True, help="pasta com as DLLs")
    ap.add_argument("--out", help="pasta de saida (padrao: <dlls>\\_REVERSE)")
    ap.add_argument("--timeout", type=int, default=3600, help="segundos por DLL no IDA (padrao 3600)")
    ap.add_argument("--jobs", type=int, default=1, help="IDAs em paralelo (padrao 1)")
    ap.add_argument("--force", action="store_true", help="refaz mesmo as ja analisadas")
    ap.add_argument("--pular-falhas", action="store_true", help="na retomada, nao repete erro/timeout")
    ap.add_argument("--only", help="lista separada por virgula de nomes de DLL")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--ext", default="dll", help="extensoes (ex.: dll,exe,ocx)")
    ap.add_argument("--usar-gui", action="store_true", help="usa ida.exe mesmo havendo idat.exe")
    ap.add_argument("--dotpeek", help="caminho do dotPeek64.exe (para abrir_no_dotpeek.bat)")
    ap.add_argument("--dotpeek-cmd", help='linha de comando de decompilacao via dotPeek, com {dll} e {out}')
    ap.add_argument("--ilspy-cmd", help='alternativa opcional, ex.: ilspycmd -p -o "{out}" "{dll}"')
    ap.add_argument("--decompile-lib", action="store_true", help="tambem decompila funcoes de biblioteca")
    ap.add_argument("--sem-asm", action="store_true", help="nao gera disasm_completo.asm")
    ap.add_argument("--sem-renomear", action="store_true")
    ap.add_argument("--csv-sep", default=";")
    cfg = ap.parse_args(argv)
    cfg.python_exe = sys.executable
    cfg.dlls = os.path.abspath(cfg.dlls)
    cfg.out = os.path.abspath(cfg.out or os.path.join(cfg.dlls, "_REVERSE"))
    os.makedirs(cfg.out, exist_ok=True)
    if not os.path.exists(cfg.ida):
        print("ERRO: nao encontrei o IDA:", cfg.ida)
        return 2
    if not os.path.isdir(cfg.dlls):
        print("ERRO: pasta das DLLs inexistente:", cfg.dlls)
        return 2

    lista = descobrir(cfg)
    arqlog = os.path.join(cfg.out, "orquestrador.log")
    log("=" * 70, arqlog)
    log(f"Pipeline {ac.VERSAO_PIPELINE} | {len(lista)} arquivo(s) | timeout={cfg.timeout}s jobs={cfg.jobs} | saida={cfg.out}", arqlog)
    log("=" * 70, arqlog)

    linhas = {}
    # retoma o CSV com TUDO que ja existe na pasta de saida (mesmo com --only)
    for n in os.listdir(cfg.out):
        m = ac.ler_json(os.path.join(cfg.out, n, "ANALISE_CONCLUIDA.json"))
        if m and m.get("linha"):
            linhas[n] = m["linha"]

    def tarefa(i, a, n):
        try:
            l = processar(cfg, a, n, i, len(lista))
        except Exception as e:
            import traceback
            l = {c: "" for c in COLUNAS}
            l.update({"dll": n, "status": "erro", "observacao": f"{type(e).__name__}: {e}",
                      "pasta": os.path.join(cfg.out, n)})
            log(traceback.format_exc(), arqlog)
        linhas[n] = l
        gravar_resumo(cfg, linhas)
        return l

    try:
        if cfg.jobs > 1:
            with cf.ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
                list(ex.map(lambda t: tarefa(*t), [(i, a, n) for i, (a, n) in enumerate(lista, 1)]))
        else:
            for i, (a, n) in enumerate(lista, 1):
                tarefa(i, a, n)
    except KeyboardInterrupt:
        log("Interrompido pelo usuario; o que foi concluido esta em resumo.csv (rode de novo para retomar).", arqlog)
        gravar_resumo(cfg, linhas)
        return 130

    atualizar_bat_dotpeek(cfg)
    try:
        ordem = dependencias_dlls.escrever(cfg.out)
        log(f"Ordem de build: {len(ordem)} grupo(s) -> ordem_build.txt", arqlog)
    except Exception as e:
        log(f"Dependencias entre DLLs falhou: {e}", arqlog)

    cont = {}
    for l in linhas.values():
        cont[l["status"]] = cont.get(l["status"], 0) + 1
    log("=" * 70, arqlog)
    log("FINAL: " + ", ".join(f"{k}={v}" for k, v in sorted(cont.items())), arqlog)
    log(f"Resumo : {os.path.join(cfg.out, 'resumo.csv')}", arqlog)
    log("=" * 70, arqlog)
    return 1 if any(l["status"] in FALHAS for l in linhas.values()) else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    sys.exit(main())
