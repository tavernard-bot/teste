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
assert S["recuperadas_retry"] == 1, S["recuperadas_retry"]          # pong volta apos reanalisar
assert S["falhas_por_categoria"] == {"chamada": 1}, S["falhas_por_categoria"]
fp = open(os.path.join(out, "falhas_priorizadas.csv"), encoding="utf-8-sig").read()
print(fp)
assert "Foo_Calc_int" in fp and "chamada" in fp
c = open(os.path.join(out, "projeto", "src", "Foo_Calc_int.c"), encoding="utf-8").read()
print(c)
assert "Exemplos de chamada" in c and "MOD_mp_TOP_:" in c and "double 273.15" in c and "bloco 0x" in c and "-> MOD_mp_LEAF_" in c
assert "recuperada no retry" in open(os.path.join(out, "projeto", "src", "pong.c"), encoding="utf-8").read()
assert not os.path.exists(os.path.join(out, "asm", "pong.asm"))
assert os.path.exists(os.path.join(out, "falhas_resumo.txt"))
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
