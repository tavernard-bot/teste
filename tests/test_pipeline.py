# -*- coding: utf-8 -*-
"""Teste do pipeline completo com IDA falso: nativa / mista / gerenciada / invalida / timeout / retomada."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)
sys.path.insert(0, RAIZ)
import pe_builder  # noqa: E402

base = tempfile.mkdtemp(prefix="pipe_")
dlls = os.path.join(base, "dlls")
os.makedirs(os.path.join(dlls, "ida", "plugins"))
open(os.path.join(dlls, "ida", "plugins", "defs.h"), "w").write("/* defs */\n")
pe_builder.construir(os.path.join(dlls, "nat.dll"))
pe_builder.construir(os.path.join(dlls, "mix.dll"), clr="mista")
pe_builder.construir(os.path.join(dlls, "man.dll"), exports=False, clr="il_only")
pe_builder.construir(os.path.join(dlls, "lento.dll"))
open(os.path.join(dlls, "lixo.dll"), "w").write("nao e PE")
fake = os.path.join(AQUI, "fake_ida.sh")
env = dict(os.environ, FAKE_MODE="hang")
cmd = [sys.executable, os.path.join(RAIZ, "orquestrar.py"), "--ida", fake, "--dlls", dlls, "--timeout", "6"]
r = subprocess.run(cmd, env=env, capture_output=True, text=True)
print(r.stdout[-1500:])
out = os.path.join(dlls, "_REVERSE")
res = {l["dll"]: l for l in json.load(open(os.path.join(out, "resumo.json"), encoding="utf-8"))}
assert res["nat"]["status"] == "ok" and res["nat"]["tipo"] == "nativa", res["nat"]
assert res["mix"]["tipo"] == "mista" and res["mix"]["status"] == "ok" and res["mix"]["gerenciada_dotpeek"]
assert res["man"]["status"] == "gerenciada" and not os.path.exists(os.path.join(out, "man", "analysis_summary.json"))
assert res["lixo"]["status"] == "nao_pe"
assert res["lento"]["status"] == "timeout"
assert os.path.exists(os.path.join(out, "_GERENCIADAS", "man.dll"))
assert os.path.exists(os.path.join(out, "_GERENCIADAS", "mix.dll"))
bat = open(os.path.join(out, "_GERENCIADAS", "abrir_no_dotpeek.bat")).read()
assert "man.dll" in bat and "mix.dll" in bat
for f in ("nat/projeto/build.bat", "nat/projeto/include/defs.h", "nat/projeto/tests/casos_teste.json",
          "nat/projeto/LEIA-ME_PROJETO.txt", "ordem_build.txt", "dependencias_dlls.json", "resumo.csv"):
    assert os.path.exists(os.path.join(out, f)), f
defs = open(os.path.join(out, "nat", "projeto", "include", "defs.h")).read()
print("defs.h do IDA copiado:", defs.strip() == "/* defs */" or "MINIMO" in defs)

# retomada: so o 'lento' deve ser refeito (timeout); os demais PULADA
env["FAKE_MODE"] = ""
r = subprocess.run(cmd, env=env, capture_output=True, text=True)
assert r.stdout.count("PULADA") == 4, r.stdout
res = {l["dll"]: l for l in json.load(open(os.path.join(out, "resumo.json"), encoding="utf-8"))}
assert res["lento"]["status"] == "ok"
# --only nao apaga as outras linhas do CSV
r = subprocess.run(cmd + ["--only", "nat", "--force"], env=env, capture_output=True, text=True)
res = {l["dll"] for l in json.load(open(os.path.join(out, "resumo.json"), encoding="utf-8"))}
assert res == {"nat", "mix", "man", "lixo", "lento"}, res
shutil.rmtree(base, ignore_errors=True)
print("OK")
