# -*- coding: utf-8 -*-
"""
gerar_projeto.py - monta o esqueleto de recompilacao de UMA DLL nativa.

Uso:  python gerar_projeto.py PASTA_DA_DLL [--ida-dir "C:\\Program Files\\IDA Professional 9.1"]

Le o que classificar_dll.py e analisar_ida.py produziram em PASTA_DA_DLL e completa
PASTA_DA_DLL\\projeto\\ com:
  NOME.def                 (nomes + ordinais; export mangled = funcao C sanitizada)
  include\\NOME.h           (prototipos das funcoes exportadas, como o IDA inferiu)
  include\\defs.h           (copiado do IDA: plugins\\defs.h; senao um minimo de apoio)
  build.bat [check]        (MSVC; flags derivadas do PE; 'check' compila cada .c isolado)
  build_gcc.bat            (se o binario veio de MinGW/gfortran)
  build_fortran.bat        (se veio de Intel Fortran: para reescrever em Fortran)
  dados\\globais.c, tabelas.c  (valores iniciais de .data/.rdata e tabelas de coeficientes)
  tests\\casos_teste.json, executar_teste.bat   (modelo do teste diferencial)
  LEIA-ME_PROJETO.txt
"""
import argparse
import glob
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402

DEFS_MINIMO = r'''/* defs.h MINIMO de apoio - o defs.h completo do IDA (plugins\defs.h) nao foi encontrado.
   Copie-o para esta pasta para o pseudocodigo Hex-Rays compilar de forma mais completa. */
#ifndef DEFS_H_MINIMO
#define DEFS_H_MINIMO
#include <stdint.h>
#include <string.h>
#include <math.h>
#ifndef _MSC_VER
typedef long long __int64;
typedef int __int32;
typedef short __int16;
typedef signed char __int8;
#endif
typedef unsigned char  _BYTE;
typedef unsigned short _WORD;
typedef unsigned int   _DWORD;
typedef unsigned long long _QWORD;
typedef unsigned char  _BOOL1;
typedef int            _BOOL4;
typedef unsigned char  uint8;
typedef unsigned short uint16;
typedef unsigned int   uint32;
typedef unsigned long long uint64;
#define LOBYTE(x)   (*((_BYTE*)&(x)))
#define LOWORD(x)   (*((_WORD*)&(x)))
#define LODWORD(x)  (*((_DWORD*)&(x)))
#define HIDWORD(x)  (*(((_DWORD*)&(x))+1))
#define HIWORD(x)   (*(((_WORD*)&(x))+1))
#define BYTE1(x)    (*(((_BYTE*)&(x))+1))
#define BYTE2(x)    (*(((_BYTE*)&(x))+2))
#define BYTE3(x)    (*(((_BYTE*)&(x))+3))
#define WORD1(x)    (*(((_WORD*)&(x))+1))
#define WORD2(x)    (*(((_WORD*)&(x))+2))
#define __PAIR64__(hi, lo) ((((uint64)(hi)) << 32) | (uint32)(lo))
#endif
'''


def _escolher_defs(ida_dir):
    if not ida_dir:
        return None
    for pat in ("plugins/defs.h", "defs.h", "*/defs.h", "*/*/defs.h"):
        achados = glob.glob(os.path.join(ida_dir, pat))
        if achados:
            return achados[0]
    return None


def _cabecalho_publico(nome, exps):
    L = [f"/* {nome}.h - interface publica recuperada (exports da DLL original).",
         "   Prototipos inferidos pelo IDA/Hex-Rays: CONFIRME tipos e convencao de chamada.",
         "   Fortran: argumentos normalmente por referencia (ponteiros); CHARACTER leva um",
         "   argumento oculto de tamanho no final. */",
         f"#ifndef {ac.identificador_c(nome).upper()}_H", f"#define {ac.identificador_c(nome).upper()}_H", "",
         '#include "defs.h"', "", "#ifdef __cplusplus", 'extern "C" {', "#endif", ""]
    for e in sorted(exps, key=lambda x: x["ordinal"]):
        p = e.get("proto") or {}
        orig = e.get("name") or f"#{e['ordinal']}"
        if e.get("tipo") == "funcao" and p.get("decl"):
            L.append(f"{p['decl']};   /* ordinal {e['ordinal']}, export '{orig}'"
                     + (f", {p['cc']}" if p.get("cc") else "") + (f", {p['nargs']} arg(s)" if p.get("nargs") is not None else "")
                     + " */")
        elif e.get("tipo") == "dado":
            L.append(f"/* dado exportado: ordinal {e['ordinal']} '{orig}' ({e.get('tamanho_item')} bytes) */")
        elif e.get("forwarder"):
            L.append(f"/* forwarder: ordinal {e['ordinal']} '{orig}' -> {e['forwarder']} */")
        else:
            L.append(f"/* sem prototipo: ordinal {e['ordinal']} '{orig}' */")
    L += ["", "#ifdef __cplusplus", "}", "#endif", "", "#endif", ""]
    return "\n".join(L)


def _def_final(nome_dll, exps_pe, exps_ida):
    """Combina exports do PE (verdade sobre nomes/ordinais) com os nomes C do IDA."""
    por_ord = {e["ordinal"]: e for e in (exps_ida or [])}
    saida = []
    for e in exps_pe:
        x = dict(e)
        i = por_ord.get(e["ordinal"])
        if i and i.get("c_name") and e.get("name") and i["c_name"] != e["name"] and not e.get("forwarder"):
            x["interno"] = i["c_name"]
        saida.append(x)
    return saida


def _escrever_def(caminho, nome_dll, exps):
    L = ["; .def gerado - mantem nomes e ordinais da DLL original",
         f'LIBRARY "{nome_dll}"', "EXPORTS"]
    for e in sorted(exps, key=lambda x: x["ordinal"]):
        nome, o = e.get("name") or "", e["ordinal"]
        data = " DATA" if e.get("data") else ""
        if e.get("forwarder"):
            L.append(f"    {nome} = {e['forwarder']} @{o}" if nome else f"    Ordinal{o} = {e['forwarder']} @{o} NONAME")
        elif not nome:
            L.append(f"    Ordinal{o} @{o} NONAME{data}")
        elif e.get("interno"):
            L.append(f"    {nome} = {e['interno']} @{o}{data}")
        else:
            L.append(f"    {nome} @{o}{data}")
    with open(caminho, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(L) + "\n")


def _bat_msvc(nome, arq64, cflags, lflags):
    vc = "x64" if arq64 else "x86"
    return f'''@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ==================================================================
REM Recompilacao de {nome} (gerado por gerar_projeto.py)
REM   build.bat          compila tudo e liga build\\{nome}.dll
REM   build.bat check    compila cada .c isolado e lista os que ainda falham
REM Para aproximar o binario original use o toolset sugerido em ..\\compiler_info.txt
REM (defina VCVARS_OVERRIDE com o vcvarsall.bat dessa versao do Visual Studio).
REM ==================================================================
set "NOME={nome}"
set "VCARCH={vc}"
set "CFLAGS={cflags}"
set "LFLAGS={lflags}"
cd /d "%~dp0"
if not exist build mkdir build
if not exist build\\obj mkdir build\\obj

if defined VCVARS_OVERRIDE goto :usar_override
where cl >nul 2>&1
if not errorlevel 1 goto :compilar
set "VSWHERE=%ProgramFiles(x86)%\\Microsoft Visual Studio\\Installer\\vswhere.exe"
if not exist "%VSWHERE%" goto :sem_vs
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto :sem_vs
call "%VSDIR%\\VC\\Auxiliary\\Build\\vcvarsall.bat" %VCARCH% >nul
goto :compilar
:usar_override
call "%VCVARS_OVERRIDE%" %VCARCH% >nul
goto :compilar
:sem_vs
echo ERRO: nao achei o Visual Studio (cl.exe). Abra um "Developer Command Prompt" ou defina VCVARS_OVERRIDE.
exit /b 1

:compilar
if /i "%~1"=="check" goto :check
(for %%f in (src\\*.c) do @echo "%%f") > build\\fontes.rsp
set "EXTRAS="
if exist dados\\globais.c set "EXTRAS=!EXTRAS! dados\\globais.c"
if exist dados\\tabelas.c set "EXTRAS=!EXTRAS! dados\\tabelas.c"
cl /nologo /LD %CFLAGS% /Fobuild\\obj\\ /Febuild\\%NOME%.dll @build\\fontes.rsp !EXTRAS! /link /DEF:%NOME%.def %LFLAGS%
exit /b %errorlevel%

:check
set /a OK=0
set /a FAIL=0
if exist build\\check.log del build\\check.log
if exist build\\falhas.txt del build\\falhas.txt
for %%f in (src\\*.c) do call :um "%%f"
echo Compilam: %OK%    Falham: %FAIL%    (detalhes: build\\check.log, build\\falhas.txt)
exit /b 0

:um
cl /nologo /c %CFLAGS% /Fobuild\\obj\\ %~1 >> build\\check.log 2>&1
if errorlevel 1 (
    set /a FAIL+=1
    echo %~1>> build\\falhas.txt
) else (
    set /a OK+=1
)
exit /b 0
'''


def _bat_gcc(nome, flags):
    return f'''@echo off
REM MinGW-w64 (o binario original parece ter vindo de gcc/gfortran)
cd /d "%~dp0"
if not exist build mkdir build
(for %%f in (src\\*.c) do @echo "%%f") > build\\fontes.rsp
gcc -shared {flags} -I include -Wno-implicit-function-declaration -o build\\{nome}.dll @build\\fontes.rsp {nome}.def
'''


def _bat_fortran(nome, flags):
    return f'''@echo off
REM Reescrita em Fortran (o binario original parece ter vindo de Intel Fortran).
REM Coloque os .f90 em fortran\\ ; ajuste as flags apos o teste diferencial.
cd /d "%~dp0"
if not exist build mkdir build
where ifx >nul 2>&1 && (set "FC=ifx") || (set "FC=ifort")
%FC% {flags} fortran\\*.f90 /exe:build\\{nome}.dll /link /DEF:{nome}.def
'''


def gerar(pasta, ida_dir=None, scripts_dir=None, python_exe=None):
    pasta = os.path.abspath(pasta)
    nome = os.path.basename(pasta.rstrip("\\/"))
    proj = os.path.join(pasta, "projeto")
    for sub in ("src", "include", "dados", "tests", "fortran"):
        os.makedirs(os.path.join(proj, sub), exist_ok=True)
    scripts_dir = scripts_dir or os.path.dirname(os.path.abspath(__file__))
    python_exe = python_exe or sys.executable
    cls = ac.ler_json(os.path.join(pasta, "classification.json"), {}) or {}
    ci = ac.ler_json(os.path.join(pasta, "compiler_info.json"), {}) or {}
    exps_pe = ac.ler_json(os.path.join(pasta, "exports_pe.json"), []) or []
    exps_ida = ac.ler_json(os.path.join(pasta, "exports_prototypes.json"), None)
    resumo = ac.ler_json(os.path.join(pasta, "analysis_summary.json"), {}) or {}
    rec = ci.get("recomendacao", {})
    arq64 = (cls.get("arquitetura") or "x64").startswith(("x64", "ARM64"))
    feito = []

    # .def
    exps = _def_final(nome, exps_pe, exps_ida)
    if exps:
        _escrever_def(os.path.join(proj, nome + ".def"), nome + ".dll", exps)
        feito.append(nome + ".def")

    # defs.h
    defs = _escolher_defs(ida_dir)
    destino = os.path.join(proj, "include", "defs.h")
    if defs:
        shutil.copyfile(defs, destino)
        feito.append("include\\defs.h (do IDA)")
    elif not os.path.exists(destino):
        with open(destino, "w", encoding="utf-8") as f:
            f.write(DEFS_MINIMO)
        feito.append("include\\defs.h (MINIMO - copie o do IDA)")

    # cabecalho publico
    if exps_ida:
        with open(os.path.join(proj, "include", nome + ".h"), "w", encoding="utf-8") as f:
            f.write(_cabecalho_publico(nome, exps_ida))
        feito.append(f"include\\{nome}.h")

    # dados globais/tabelas
    for a in ("globais.c", "tabelas.c"):
        orig = os.path.join(pasta, "data", a)
        if os.path.exists(orig):
            shutil.copyfile(orig, os.path.join(proj, "dados", a))
    # tipos.h / funcoes.h ja gravados pelo IDA em include\; garante existencia
    for a in ("tipos.h", "funcoes.h"):
        p = os.path.join(proj, "include", a)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"/* {a}: o IDA nao gerou este arquivo (analise falhou/incompleta). */\n")

    # flags
    fam = rec.get("familia", "")
    arch_flag = (resumo.get("flag_arch_sugerida") or "").split(" ")[0]
    cflags = ["/nologo", "/TC", "/O2", "/W0", "/D_CRT_SECURE_NO_WARNINGS", "/Iinclude", "/Isrc"]
    fl_comp = [f for f in rec.get("flags_compilador", []) if f in ("/fp:strict", "/fp:precise", "/MD", "/MT")]
    cflags += fl_comp or ["/fp:strict", "/MD"]
    if arch_flag.startswith("/arch:"):
        cflags.append(arch_flag)
    lflags = [f for f in rec.get("flags_link", []) if f != "/DLL" and not f.startswith("/MACHINE")]
    lflags.append("/MACHINE:" + ("X64" if arq64 else "X86"))
    with open(os.path.join(proj, "build.bat"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write(_bat_msvc(nome, arq64, " ".join(cflags), " ".join(lflags)))
    feito.append("build.bat")
    if fam in ("gcc", "gnu_fortran", "clang"):
        with open(os.path.join(proj, "build_gcc.bat"), "w", encoding="utf-8", newline="\r\n") as f:
            f.write(_bat_gcc(nome, " ".join(rec.get("flags_compilador", ["-O2"]))))
        feito.append("build_gcc.bat")
    if fam in ("intel_fortran", "compaq_fortran") or fam.endswith("fortran"):
        fl = [x for x in rec.get("flags_compilador", ["/dll"])]
        with open(os.path.join(proj, "build_fortran.bat"), "w", encoding="utf-8", newline="\r\n") as f:
            f.write(_bat_fortran(nome, " ".join(fl)))
        feito.append("build_fortran.bat")

    # teste diferencial
    casos = os.path.join(proj, "tests", "casos_teste.json")
    if exps_ida:
        try:
            import teste_diferencial as td
            n = td.gerar_modelo(os.path.join(pasta, "exports_prototypes.json"), casos,
                                original=os.path.join(pasta, nome + ".dll"),
                                recompilada=os.path.join(proj, "build", nome + ".dll"))
            feito.append(f"tests\\casos_teste.json ({n} funcao(oes))")
        except Exception as e:  # nao impede o resto
            feito.append(f"tests\\casos_teste.json FALHOU: {e}")
    with open(os.path.join(proj, "tests", "executar_teste.bat"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write(f'@echo off\r\ncd /d "%~dp0"\r\n"{python_exe}" "{os.path.join(scripts_dir, "teste_diferencial.py")}" '
                f'executar casos_teste.json --saida relatorio_diferencial %*\r\n')

    # LEIA-ME
    L = [f"PROJETO DE RECOMPILACAO - {nome}", "=" * 60,
         f"Tipo: {cls.get('classificacao')}   Arquitetura: {cls.get('arquitetura')}",
         f"Compilador sugerido : {rec.get('compilador')}",
         f"Flags (palpite)     : {' '.join(rec.get('flags_compilador', []))}",
         f"Funcoes: {resumo.get('funcoes')}  usuario={resumo.get('funcoes_usuario')}  lib={resumo.get('funcoes_lib')}  "
         f"thunk={resumo.get('funcoes_thunk')}  runtime={resumo.get('funcoes_runtime')}",
         f"Decompiladas: {resumo.get('decompiladas')}  falhas: {resumo.get('falhas_decompilador')}  "
         f"ISA: {resumo.get('isa_contagem')} -> {resumo.get('flag_arch_sugerida')}", "",
         "FLUXO SUGERIDO",
         "  1. Leia ..\\ordem_reescrita.csv: reescreva de nivel 0 (folhas) para cima.",
         "  2. src\\<funcao>.c traz cabecalho com quem chama/quem e chamado, globais e strings usadas.",
         "  3. Funcoes que falharam: src\\<funcao>.c contem o disassembly; ver ..\\decompile_failures.txt.",
         "  4. Constantes/tabelas: dados\\tabelas.c e ..\\data\\tabelas_candidatas.csv (coeficientes).",
         "  5. build.bat check  -> quantos .c ja compilam;  build.bat -> liga a DLL com o mesmo .def.",
         "  6. tests\\executar_teste.bat -> compara numeros original x recompilada.",
         "  7. comparar_dlls.py -> compara exports/numero de funcoes/tamanhos (e prepara o BinDiff).", ""]
    if rec.get("observacoes"):
        L.append("OBSERVACOES")
        L += ["  * " + o for o in rec["observacoes"]]
    with open(os.path.join(proj, "LEIA-ME_PROJETO.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return feito


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pasta")
    ap.add_argument("--ida-dir")
    a = ap.parse_args()
    for x in gerar(a.pasta, a.ida_dir):
        print("  +", x)
    return 0


if __name__ == "__main__":
    sys.exit(main())
