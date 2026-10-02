# INFO.md - guia do agente de recompilação

Público: um agente (ou pessoa) que vai **recompilar** DLLs a partir do que o `analisar_dlls.bat`
gerou. O objetivo deste guia é que você **não varra arquivos**: quase tudo já está indexado,
ordenado e resumido. Leia o que a seção 2 manda, na ordem em que ela manda, e consulte o resto
**sob demanda** (grep por nome/endereço).

> Convenção: `R` = pasta de saída do lote (padrão `<DLL_DIR>\_REVERSE`), `D` = `R\NOME_DLL`
> (uma DLL), `P` = `D\projeto`.

---

## 1. Regras de ouro

1. **Nunca leia por inteiro**: `D\pseudocode_hexrays.c` (concatenação de tudo), `D\disasm_completo.asm`,
   `D\strings.txt`, `D\data\data_globals.csv`, `D\data\*.bin`, `D\functions.txt`.
   São fontes de **consulta** (grep por nome ou endereço), não de leitura.
2. **Uma função = um arquivo** em `P\src\`. O cabeçalho dele já traz o contexto (quem chama, externos,
   globais, strings). Leia só esse arquivo para reescrever aquela função.
3. **Siga a ordem de `D\ordem_reescrita.csv`** (folhas primeiro). Quando você chega numa função, tudo que
   ela chama já foi reescrito e testado.
4. **Não reescreva** funções `lib`, `thunk` e `runtime`: use a equivalente da libc/libm/runtime.
5. **Número vence byte**: o critério de pronto é o teste diferencial (seção 7), não bytes iguais.
6. **Não edite `D\` fora de `P\`**, e **não rode o lote com `--force` sobre uma pasta onde você já
   trabalhou** (regrava `projeto\src\`, `.def`, `build.bat`). Trabalhe numa cópia (seção 4, passo 0).
7. Tudo aqui é **indício + heurística** (classificação user/lib, tabelas, flags, protótipos).
   Confirme no pseudocódigo/asm antes de confiar quando algo parecer estranho.

---

## 2. Triagem (5 leituras, nesta ordem)

| # | Arquivo | O que extrair | Tamanho |
|---|---------|---------------|---------|
| 1 | `R\resumo.csv` (sep `;`) | status e tipo de cada DLL; quais valem a pena | 1 linha/DLL |
| 2 | `R\ordem_build.txt` | **ordem entre DLLs** (dependências primeiro; ciclos marcados) e runtimes de terceiros | curto |
| 3 | `P\LEIA-ME_PROJETO.txt` | compilador sugerido, contagens, observações da DLL | curto |
| 4 | `D\compiler_info.txt` | toolset, CRT, runtimes, PDB, timestamp, flags | ~50 linhas |
| 5 | `D\analysis_summary.json` | contagens, ISA (x87/SSE/AVX/FMA), fases com erro, avisos | 1 JSON |

### 2.1 Colunas de `resumo.csv`
`dll;status;tipo;arquitetura;classificacao;compilador_sugerido;toolset_linker;exports;funcoes;
funcoes_usuario;funcoes_lib;decompiladas;falhas_decompilador;tabelas_candidatas;classes_rtti;
gerenciada_dotpeek;segundos;ida_rc;observacao;pasta`

### 2.2 O que fazer com cada `status` / `tipo`

| status / tipo | Significado | Ação |
|---|---|---|
| `ok` + `nativa` | tudo gerado | trabalho normal (seção 4) |
| `ok` + `mista` | C++/CLI: parte nativa no IDA, gerenciada à parte | nativa pela seção 4; gerenciada: `R\_GERENCIADAS\` + dotPeek |
| `parcial` | IDA terminou mas pulou funções por prazo ou teve fase com erro | ver `analysis_summary.json` (`puladas_prazo`, `fases`); funções puladas aparecem em `decompile_failures.csv` com motivo "prazo" |
| `timeout` | IDA foi encerrado; saídas parciais | pedir novo run com `--timeout` maior (`--only NOME`); enquanto isso use o que há em `P\src` |
| `erro` | IDA falhou | ler `D\ida_script_error.txt`, `D\erro_fase_*.txt`, fim de `D\ida.log`; não tente recompilar daí |
| `gerenciada` | .NET IL-only, **não** passou pelo IDA | decompilar no dotPeek (`R\_GERENCIADAS\abrir_no_dotpeek.bat`); não há `P\src` |
| `nao_pe` | arquivo não é PE | ignorar |

Escolha a DLL por `ordem_build.txt`: as **primeiras** (sem dependências entre as DLLs da pasta) vêm
primeiro. DLLs que importam outra da pasta devem ser linkadas contra a **versão recompilada** dela.

---

## 3. Mapa dos arquivos (o que é, quando usar)

### 3.1 Dentro de `D\` (uma DLL)

| Arquivo | Use para | Observação |
|---|---|---|
| `ordem_reescrita.csv` | **fila de trabalho** | `ordem;nivel(0=folha);ea;nome;tipo;tamanho;recursivo;grupo_scc;chama` |
| `functions.json` | índice completo por função | chaves abaixo (3.2); filtre por `kind`, `exported`, `falha` |
| `exports_prototypes.json` | **interface pública**: protótipo, convenção, arquivo `.c` de cada export | seção 3.3 |
| `callgraph.json` / `callgraph_edges.csv` | quem chama quem (`chamador;ea_chamador;chamado;ea_chamado`) | use p/ priorizar e achar dependências |
| `decompile_failures.csv` | funções que o Hex-Rays não decompilou | `ea;nome;tipo;tamanho;blocos;motivo`; o `.c` correspondente contém o disassembly (exceto motivo "prazo": essas não têm `.c`; pedir novo run) |
| `funcoes_biblioteca.txt` | o que **não** reescrever (FLIRT, thunks, runtime) | só consulte por grep |
| `renomeacoes.csv` | `ea;nome_original;nome_c` | traduz nome mangled/C++ ↔ nome C usado nos `.c` |
| `compiler_info.json/.txt` | compilador, flags, CRT, runtimes | seção 6 |
| `exports_pe.json`, `imports_pe.json/.txt` | verdade do PE sobre exports/imports | quando precisar do ordinal/forwarder |
| `classes_rtti.json`, `classes_skeleton.hpp` | classes C++ (vtables, bases) | só se `classes_rtti > 0` |
| `data\` | dados globais e tabelas | seção 5 |
| `asm\<funcao>.asm` | disassembly das funções que falharam | idem trecho dentro do `.c` |
| `disasm_completo.asm` | fallback para trechos numéricos ilegíveis | **só grep/trecho** |
| `strings.txt` | mensagens de erro/formatos | **só grep** |
| `ida.log`, `ida_script_error.txt`, `erro_fase_*.txt` | diagnóstico | só se houver problema |

### 3.2 Chaves de `functions.json` (por função)
`ea_hex, name, name_original, demangled, size, kind, nivel, grupo, recursivo, exported,
export_ordinals, virtual, externs, indirect_calls, nblocks, decompilado, arquivo, proto, falha`

* `arquivo` = **caminho relativo (a `D\`) exato do `.c`**. Use-o; **não reconstrua** o nome do
  arquivo a partir do nome da função (underscores finais e colisões são alterados).
* `kind`:

| kind | Significado | Reescrever? |
|---|---|---|
| `user` | alcançável a partir de um export | **sim** |
| `init` | alcançável só pelo entry point (DllMain/inicialização) | só se o conteúdo for lógica do autor (não CRT) |
| `orphan` | só chamada por ponteiro/vtable/callback | **sim** (veja `virtual`, `indirect_calls`) |
| `lib` | reconhecida pelo FLIRT | não: use a biblioteca |
| `thunk` | salto/wrapper | não |
| `runtime` | nome de runtime/CRT (`__scrt_`, `__intel_`, `for_`, `__security_`...) | não: mapear para o equivalente |

* `nivel`: 0 = não chama nenhuma outra função de usuário (**folha**). `recursivo`/`grupo`: funções do mesmo
  grupo se chamam em ciclo - reescreva o grupo junto.

### 3.3 `exports_prototypes.json`
Por export: `ordinal, name, c_name, demangled, tipo (funcao|dado|forwarder), kind, decompilado, arquivo,
forwarder, proto{decl, ret, cc, nargs, args[{tipo,nome}], fonte}`.
* `c_name` = nome da função C a implementar; se diferente de `name` (C++ mangled), o `.def` já faz
  `name = c_name`.
* `proto.fonte`: `hexrays` (inferido) > `tipo_ida` > `guess`. **Em Fortran os tipos inferidos são
  frequentemente imprecisos** (ver seção 8).

### 3.4 Dentro de `P\` (projeto)

| Caminho | Conteúdo |
|---|---|
| `src\<funcao>.c` | pseudocódigo (ou disassembly em comentário se falhou) + cabeçalho de contexto |
| `src\src_ordem.txt` | lista numerada dos `.c` já em ordem folhas-primeiro |
| `include\defs.h` | `defs.h` do IDA (ou um mínimo): `_DWORD`, `LODWORD`, `BYTE1`... |
| `include\funcoes.h` | protótipo de **todas** as funções de usuário |
| `include\tipos.h` | structs/enums locais do IDA (best-effort) |
| `include\NOME.h` | protótipos dos exports |
| `NOME.def` | exports com **mesmos nomes e ordinais** da original |
| `dados\globais.c`, `dados\tabelas.c` | valores iniciais de globais e tabelas de doubles |
| `build.bat` / `build.bat check` | liga a DLL / compila cada `.c` isolado e lista falhas |
| `build_gcc.bat`, `build_fortran.bat` | só quando a família do compilador pede |
| `fortran\` | pasta para reescritas em Fortran (opcional) |
| `tests\casos_teste.json`, `tests\executar_teste.bat` | modelo do teste diferencial |
| `LEIA-ME_PROJETO.txt` | resumo + fluxo |

#### Cabeçalho de cada `src\*.c` (já mastigado para você)
```
/*  Funcao   : nome_c
    Original : nome_mangled   (demangled)
    EA / tam : 0x... / N bytes
    Tipo     : user [exportada ord=N] [virtual] [RECURSIVA/ciclo]
    Nivel    : k (0 = folha)
    Chama    : funcoes de usuario chamadas
    Externos : DLL!api chamadas (imports)
    Globais  : simbolos de dados usados (r/w/o)
    Strings  : literais referenciados
    Chamadas indiretas: n   */
```
Isso dispensa procurar xrefs: a dependência de dados e de chamadas está ali.

---

## 4. Fluxo por DLL (loop de trabalho)

**Passo 0 - preparar (uma vez por DLL)**
1. Copie `D\projeto` para uma pasta de trabalho **fora de `_REVERSE`** (ex.: `trabalho\NOME\`) e guarde
   `src\` original como referência somente-leitura (`ref\`). Assim um novo run do lote não apaga seu trabalho
   e você pode fazer `diff` contra o pseudocódigo puro.
2. Em `tests\casos_teste.json` ajuste `original` (a DLL original em `D\NOME.dll`) e `recompilada`
   (o `build\NOME.dll` da pasta nova). `executar_teste.bat` usa caminhos relativos ao seu próprio local.
3. Crie `PROGRESSO.csv` (`funcao;status;compila;testado;obs`) e marque as funções conforme avança;
   é o seu índice de retomada.
4. Se o toolset sugerido for antigo (ex.: VS2010) e você tiver essa versão, defina `VCVARS_OVERRIDE`
   antes do `build.bat`.

**Passo 1 - fila**: abra `D\ordem_reescrita.csv`. Trabalhe de cima para baixo. Para cada linha:

1. Abra `D\<arquivo>` (campo `arquivo` de `functions.json`) ou o `.c` pelo nome em `src\`.
2. Leia o cabeçalho; se é **export**, pegue o protótipo em `exports_prototypes.json` (ou em `include\NOME.h`).
3. Reescreva o corpo (seção 8 traz as armadilhas). Troque nomes `v1,a1...` por nomes semânticos
   **só depois** de o teste passar - nomes não afetam o resultado, tempo sim.
4. Constantes/tabelas: **não digite números**; use `dados\tabelas.c` / `globais.c` (seção 5).
5. `build.bat check` -> a função deve compilar isolada.
6. Teste diferencial dessa função (seção 7). Só avance quando passar.

**Passo 2 - funções que falharam** (`decompile_failures.csv`): o `.c` traz o disassembly. Priorize por
**quantidade de chamadores** (`callgraph.json`) e por serem exportadas. Funções pequenas (`tamanho`/`blocos`
baixos) costumam ser rápidas de reescrever a partir do asm; grandes, deixe para o fim ou compare com a
saída do teste para deduzir o algoritmo.

**Passo 3 - liga e valida a DLL**: `build.bat` (usa o mesmo `.def`). `LNK2001` num export = função ainda
não implementada/nome diferente. Depois, teste diferencial completo e `comparar_dlls.py` (seção 9).

---

## 5. Dados globais, constantes e tabelas (o coração numérico)

Consulta, não leitura. Em ordem de preferência:

1. **`dados\tabelas.c`**: tabelas de doubles candidatas **que têm função usuária**, como `const double tab_<nome>[N]`,
   com 17 dígitos significativos (ida-e-volta exata). Copie/inclua; não redigite.
2. **`D\data\tabelas_candidatas.csv`**: `segmento;ea;tipo;n_valores;nome;usada_por;primeiros_valores`.
   Use para saber **qual função usa qual tabela** e conferir tamanho antes de aceitar o array.
   (Heurística: sequências de doubles plausíveis; confirme no uso - o fim da tabela pode estar errado.)
3. **`dados\globais.c`**: globais referenciadas por código, com valor inicial. Cada uma é definida
   separadamente: **se o código original faz aritmética de ponteiro entre itens vizinhos**
   (`&tab[i+1]` caindo no próximo símbolo), use o `.bin` do segmento: `D\data\<segmento>.bin`
   (ex.: `rdata.bin`; offset = `ea - base_do_segmento`, bases em `D\data\segmentos_dados.txt`).
4. **`D\data\constantes_float.csv`**: constantes escalares float/double (`ea;nome;tipo;valor;n_xrefs;usado_por`).
5. **`D\data\data_globals.csv`**: tudo de `.data/.rdata/.bss`. Grande: **filtre** por `ea`/`nome`/`usado_por`.

Dicas:
* Descobrir quem usa um endereço: `usado_por` (CSV) ou `Globais` no cabeçalho do `.c`.
* Variáveis em `.data` com `w` (escrita) são **estado** (COMMON/module vars/caches) - declare-as globais
  mutáveis e mantenha a ordem de inicialização.
* Para ler um double cru de um `.bin` em Python: `struct.unpack_from("<d", dados, off)[0]`.

---

## 6. Compilador e flags (reprodução numérica)

Fonte: `D\compiler_info.json` -> `recomendacao{familia, compilador, flags_compilador, flags_link, observacoes}`.

| `familia` | Caminho sugerido |
|---|---|
| `intel_fortran` | reescrever em C com `build.bat` **ou** em Fortran em `fortran\` com `build_fortran.bat` (ifx/ifort, `/fp:source`, `/Qprec-div`, `/Qftz-`) |
| `gnu_fortran` / `gcc` / `clang` | `build_gcc.bat` (MinGW-w64) |
| `msvc` | `build.bat` (toolset do campo `toolset_pelo_linker`) |
| `dotnet` | não se aplica (dotPeek) |

Pontos que mais afetam **números**:
* `analysis_summary.json -> isa_contagem / flag_arch_sugerida`: se há **x87** em 32 bits, os intermediários
  podem ter 80 bits -> use `/arch:IA32` e `/fp:strict`; se há **FMA/AVX**, `/arch:AVX2` e **desligue contração**
  quando precisar de igualdade (`/fp:strict`, `-ffp-contract=off`).
* `/O2` pode reordenar; para depurar divergência, compile a função com `/Od /fp:strict` primeiro.
* `runtimes` (Intel/MinGW): são **dependências em tempo de execução** do teste (`dll_dirs` em `casos_teste.json`).
* `observacoes` pode alertar: arquivo empacotado (UPX/entropia), LTCG/PGO (funções fundidas/inlinadas),
  timestamp de build reprodutível.
* Math: `__svml_*` / `__libm_*` ≈ `sin/exp/pow...`; diferenças de **alguns ULPs** são esperadas ao trocar a
  libm - use tolerância (`rtol`) em vez de exigir bit-exatidão, salvo prova de que o original é só aritmética básica.

---

## 7. Teste diferencial (como saber que está certo)

1. `P\tests\casos_teste.json` já vem com **modelo** por export (tipos inferidos). **Revise**: `tipo`, `n`
   (tamanho de arrays), `dir` (`in|out|inout`), `modo` (`ref` = ponteiro, padrão Fortran; `val`), e crie `casos`.
2. Gere entradas realistas a partir de `strings.txt`/comentários/uso (faixas físicas: T, P, composição) e use
   `"fuzz": {"n":100,"seed":1,"faixas":{"T":[200,1500]},"escala":{"P":"log"},"normalizar":["x"]}`.
3. `tests\executar_teste.bat` (ou `python teste_diferencial.py executar casos_teste.json --saida relatorio`).
4. Leia **`relatorio.csv`** (`funcao;caso;status;campo;original;recompilada;erro_abs;erro_rel;ulps;entradas`),
   não o console. `status`: `ok`, `divergente`, `ambos_crash/erro`, `orig_crash_recomp_ok` etc.
   Divergências em **um** campo costumam apontar a linha exata (índice do array, retorno, código de erro).
5. Execute por função (`--funcao NOME`) enquanto desenvolve; rode tudo no fim.
6. Cada DLL roda em processo separado: crash ou `STOP` do runtime vira resultado, não derruba o teste.
   Python deve ter o **mesmo número de bits** da DLL.
7. `ambos_crash` conta como igual (mesmo comportamento) - mas investigue se não for intencional.

---

## 8. Armadilhas ao reescrever o pseudocódigo

**Hex-Rays**
* `LODWORD/HIDWORD/BYTE1/_QWORD/_DWORD`: vêm de `defs.h`; mantenha o include enquanto o código for pseudocódigo
  e elimine aos poucos.
* `*(double *)(a1 + 8 * i)`: acessos por offset = **array/struct** de verdade. Declare o tipo e confira com o uso
  em chamadores (`callgraph.json`).
* `__fastcall`/`__usercall`/`__spoils`: ruído de convenção; na DLL final use a convenção de **export**
  (`proto.cc` e x86 stdcall decorado -> `.def`).
* Variáveis `v1..vN` e `LABEL_n: goto`: reestruture só depois de testar; mudanças prematuras escondem bugs.
* Se o protótipo inferido parece errado (nº de argumentos, ponteiro vs valor), ele **é** suspeito: confirme no
  asm (registradores usados na entrada) antes de mudar o `.def`/header.

**Fortran (Intel/gfortran)**
* Argumentos **por referência** (ponteiros); `CHARACTER` leva **tamanho oculto no fim** da lista; arrays em
  **ordem de coluna** (`a[i + n*j]`) e índices **1-based** no código fonte original.
* Nomes: `MODULO_mp_FUNCAO_` = procedimento de módulo (Intel); `__mod_MOD_proc` (gfortran).
  `D\data\data_globals.csv` mostra variáveis de módulo/COMMON como globais.
* Chamadas `for_*` (runtime Intel) = I/O, STOP, alocação etc. Nomes comuns: `for_write_seq_*`, `for_read_*`,
  `for_stop_core`, `for_alloc_allocatable`. Procure a string de formato em `Strings` do cabeçalho; I/O e STOP
  quase nunca afetam o número - substitua por equivalentes simples, **exceto** onde o código de erro/saída
  alimenta o resultado.
* Retornos de `CHARACTER`/`COMPLEX` seguem convenção especial: o harness não cobre; teste via wrapper.

**C++**
* `classes_rtti.json` lista vtables e bases; `virtual: true` em `functions.json` marca métodos virtuais.
  `orphan` + `indirect_calls` = despacho por ponteiro/vtable - o chamador não aparece no grafo direto.

---

## 9. Verificação final por DLL

1. `build.bat` com o `.def`: sem `LNK2001`.
2. `python teste_diferencial.py executar ...`: todos os casos `ok`.
3. `python comparar_dlls.py D <caminho\build\NOME.dll> --ida "<ida.exe>"` (ou `--sem-ida` para só o PE):
   lê `D\comparacao\comparacao.md` - exports (nomes+ordinais), imports (runtime diferente?), seções,
   nº de funções, tamanho de exportadas muito diferente (>50%) e chamadas externas diferentes nas exportadas.
   (O BinDiff pode ser aberto com os dois `.i64` listados no relatório.)
4. Atualize `PROGRESSO.csv` e registre no `LEIA-ME` da DLL o que ficou aproximado.

---

## 10. Comandos de consulta rápida

Python (qualquer SO; rode na pasta `D`):
```python
import json, csv
F = {f["name_original"]: f for f in json.load(open("functions.json", encoding="utf-8"))}
print(F["NOME_MANGLED_OU_ORIGINAL"]["arquivo"])                       # caminho do .c
exp = [e for e in json.load(open("exports_prototypes.json", encoding="utf-8")) if e["tipo"] == "funcao"]
folhas = [f for f in F.values() if f["kind"] in ("user","orphan","init") and f["nivel"] == 0]
falhas = [f["name"] for f in F.values() if f["falha"]]
```
PowerShell:
```powershell
Select-String -Path D\data\data_globals.csv -Pattern "0x180004A20"      # quem/que e esse endereco
Select-String -Path D\strings.txt -Pattern "formato|erro" | Select -First 20
Get-Content D\projeto\build\falhas.txt                                   # .c que ainda nao compilam
```

---

## 11. Resumo do atalho (TL;DR)

1. `resumo.csv` -> escolha DLL por `ordem_build.txt`.
2. `LEIA-ME_PROJETO.txt` + `compiler_info.txt` + `analysis_summary.json` (flags/ISA).
3. Copie `projeto\` para uma pasta de trabalho; guarde `src\` como `ref\`.
4. Para cada linha de `ordem_reescrita.csv`: ler **só** o `.c` -> reescrever -> `build.bat check` -> teste.
5. Tabelas: `tabelas.c`; ponteiros entre vizinhos: `.bin`. Falhas: asm dentro do `.c`.
6. Fim: `build.bat` + teste diferencial completo + `comparar_dlls.py`.
