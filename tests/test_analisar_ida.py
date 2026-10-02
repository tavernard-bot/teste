# -*- coding: utf-8 -*-
"""Teste de fumaca: executa analisar_ida.py contra o IDA falso e confere as saidas."""
import json
import os
import runpy
import shutil
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)
sys.path.insert(0, RAIZ)
import mock_ida  # noqa: E402

out = tempfile.mkdtemp(prefix="mockida_")
os.environ["IDA_OUTPUT"] = out
os.environ["RECOVERY_SCRIPTS"] = RAIZ
mock_ida.install()
runpy.run_path(os.path.join(RAIZ, "analisar_ida.py"), run_name="__main__")

rc = sys.modules["ida_pro"].rc
assert rc == 0, f"rc={rc}"
S = json.load(open(os.path.join(out, "analysis_summary.json"), encoding="utf-8"))
print(json.dumps({k: S[k] for k in ("status", "funcoes", "funcoes_usuario", "funcoes_por_tipo",
                                    "decompiladas", "falhas_decompilador", "isa_contagem",
                                    "flag_arch_sugerida", "tabelas_candidatas")}, indent=1))
fases_erro = {k: v for k, v in S["fases"].items() if v["status"] != "ok"}
assert not fases_erro, fases_erro
assert S["funcoes"] == 9
assert S["funcoes_por_tipo"]["lib"] == 1 and S["funcoes_por_tipo"]["thunk"] == 1
assert S["funcoes_por_tipo"]["runtime"] == 2
assert S["falhas_decompilador"] == 1 and S["decompiladas"] == 4, (S["decompiladas"], S["falhas_decompilador"])
ordem = open(os.path.join(out, "ordem_reescrita.csv"), encoding="utf-8-sig").read().splitlines()
print("\n".join(ordem))
assert os.path.exists(os.path.join(out, "projeto", "src", "MOD_mp_LEAF.c"))
assert os.path.exists(os.path.join(out, "asm"))
for f in ("decompile_failures.txt", "exports_prototypes.json", "data/tabelas_candidatas.csv",
          "data/tabelas.c", "data/globais.c", "projeto/include/funcoes.h", "renomeacoes.csv",
          "callgraph.json", "disasm_completo.asm", "classes_rtti.json"):
    assert os.path.exists(os.path.join(out, f)), f
print(open(os.path.join(out, "decompile_failures.txt"), encoding="utf-8").read())
print(open(os.path.join(out, "data", "tabelas_candidatas.csv"), encoding="utf-8-sig").read())
print(open(os.path.join(out, "projeto", "src", "MOD_mp_TOP.c"), encoding="utf-8").read())
shutil.rmtree(out, ignore_errors=True)
print("OK")
