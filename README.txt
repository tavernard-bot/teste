RECUPERACAO DE DLLs - IDA PRO 9.1 (+ dotPeek)
==============================================

VERSAO 5  -  foco: facilitar a RECOMPILACAO

Configuracao (no inicio do analisar_dlls.bat):
  IDA         = C:\Program Files\IDA Professional 9.1\ida.exe
  PYTHON      = C:\Users\taver\AppData\Local\Python\pythoncore-3.14-64\python.exe
  DLL_DIR     = D:\DLLs\ze
  TIMEOUT_SEG = 3600     (tempo maximo do IDA por DLL)
  JOBS        = 1        (IDAs em paralelo)
  DOTPEEK     =          (opcional: caminho do dotPeek64.exe)

Arquivos (todos na mesma pasta; a subpasta ida_scripts\ tambem funciona):
  analisar_dlls.bat      ponto de entrada (configuracao + chama o orquestrar.py)
  orquestrar.py          controla o lote: classifica, roteia, timeout, retomada, CSV
  classificar_dll.py     analise do PE (sem IDA): tipo, compilador, .def
  analisar_ida.py        script do IDAPython (roda dentro do IDA)
  analise_comum.py       funcoes compartilhadas (grafo, tabelas, nomes, .def)
  gerar_projeto.py       monta projeto\ de recompilacao de cada DLL nativa
  dependencias_dlls.py   dependencias entre as DLLs da pasta + ordem de build
  comparar_dlls.py       reanalisa a DLL recompilada e compara com a original
  teste_diferencial.py   harness ctypes: original x recompilada, numero a numero
  tests\                 testes (IDA simulado) - ver "Testes" no fim

Como usar
---------
  analisar_dlls.bat                      analisa tudo (retoma de onde parou)
  analisar_dlls.bat --force              refaz tudo
  analisar_dlls.bat --only ze1,ze2       so essas DLLs
  analisar_dlls.bat --jobs 3             3 IDAs em paralelo
  analisar_dlls.bat --timeout 7200       timeout por DLL
  analisar_dlls.bat --pular-falhas       na retomada nao repete erro/timeout
  analisar_dlls.bat --decompile-lib      decompila tambem funcoes de biblioteca
  analisar_dlls.bat --recursive          procura DLLs em subpastas
  analisar_dlls.bat --ext dll,exe,ocx    outras extensoes
  analisar_dlls.bat --dotpeek-cmd "..."  CLI de decompilacao ({dll} e {out})
  analisar_dlls.bat --sem-asm            nao gera disasm_completo.asm (mais rapido)

Roteamento por tipo
-------------------
  nativa      -> IDA / Hex-Rays
  mista       -> IDA (so a parte nativa) + dotPeek (parte gerenciada)   [C++/CLI]
  gerenciada  -> SO dotPeek. NAO passa pelo IDA (IL-only; ReadyToRun tambem)
  invalida    -> registrada como nao_pe no CSV

  O dotPeek e uma aplicacao grafica; nao conheco CLI de exportacao documentada
  para ele. Por isso o lote copia as DLLs .NET para _REVERSE\_GERENCIADAS\ e gera
  _REVERSE\_GERENCIADAS\abrir_no_dotpeek.bat (abre todas de uma vez). No dotPeek:
  selecionar as assemblies no Assembly Explorer > botao direito > "Export to
  Project...". Se voce tiver um comando que decompila por linha de comando, passe
  --dotpeek-cmd "comando {dll} {out}" (tambem existe --ilspy-cmd como alternativa).

Saida por DLL: <DLL_DIR>\_REVERSE\NOME_DLL\
------------------------------------------
  Classificacao (sem IDA)
    SUMMARY.txt classification.txt/.json architecture.txt clr_info.json
    exports_pe.json imports_pe.txt imports_pe.json
    compiler_info.json / .txt      [item 1]
  IDA - listas
    functions.txt functions.json segments.txt imports_ida.txt exports_ida.txt strings.txt
    analysis_summary.txt / .json   (status, contagens, ISA, fases, avisos)
  IDA - recompilacao
    exports_prototypes.json                    [item 2]
    funcoes_biblioteca.txt                     [item 3]
    pseudocode_hexrays.c  (SO codigo do usuario, folhas primeiro)
    callgraph.json callgraph_edges.csv ordem_reescrita.csv      [item 4]
    projeto\src\<funcao>.c  (um arquivo por funcao)             [item 4]
    data\data_globals.csv constantes_float.csv tabelas_candidatas.csv
    data\tabelas.c globais.c data\<segmento>.bin                [item 5]
    decompile_failures.txt/.csv  asm\<funcao>.asm               [item 6]
    disasm_completo.asm                                         [item 7]
    classes_rtti.json classes_skeleton.hpp                      [item 8]
    renomeacoes.csv (simbolos mangled -> nomes C validos)
  Projeto de recompilacao                                       [item 10]
    projeto\NOME.def  projeto\include\{NOME.h,defs.h,funcoes.h,tipos.h}
    projeto\build.bat  (build.bat check = quantos .c ja compilam)
    projeto\build_gcc.bat / build_fortran.bat (quando aplicavel)
    projeto\dados\  projeto\tests\  projeto\fortran\  projeto\LEIA-ME_PROJETO.txt
  Controle
    ANALISE_CONCLUIDA.json/.txt   (marca de retomada: sha256 + status)
    ida.log

Saida do lote: <DLL_DIR>\_REVERSE\
  resumo.csv / resumo.json    status, arquitetura, tipo, funcoes, falhas...   [item 15]
  dependencias_dlls.json/.csv, dependencias_externas.csv, ordem_build.txt     [item 9]
  _GERENCIADAS\               DLLs .NET + abrir_no_dotpeek.bat
  orquestrador.log

  Status no CSV: ok | parcial | erro | timeout | gerenciada | nao_pe
  O CSV usa ';' (abre direto no Excel pt-BR). Mude com --csv-sep ",".

O que cada item da lista virou
------------------------------
  1  Compilador/flags: classificar_dll.py le linker, Rich Header (prodid/build/count),
     timestamp (detecta /Brepro), PDB (RSDS, GUID, age), tipos de debug (POGO/ILTCG),
     DllCharacteristics, VersionInfo, strings (Intel(R) Fortran, forrtl, GCC:, clang...),
     CRT/runtimes importados e sugere compilador + flags -> compiler_info.txt.
     O analisar_ida.py ainda mede o uso de x87/SSE/AVX/FMA e sugere /arch:...
  2  .def com nomes e ordinais (forwarders, NONAME, DATA) + prototipos (tipo, convencao,
     nargs) em exports_prototypes.json e include\NOME.h. Demangle: C++ pelo IDA, Fortran
     (MODULO_mp_FUNCAO_ -> MODULO::FUNCAO; gfortran __mod_MOD_proc). Export com nome
     mangled vira "mangled = funcao_C" no .def.
  3  Cada funcao e marcada: user | init | orphan | lib (FLIRT) | thunk | runtime
     (por nome: __scrt_, __intel_, for_, __security_, CRT...). So user/init/orphan sao
     decompiladas por padrao. "user" = alcancavel a partir de um export; "init" =
     so alcancavel pelo entry point (DllMain/CRT); "orphan" = chamada por ponteiro/vtable.
  4  projeto\src\<funcao>.c com cabecalho (quem chama, externos, globais, strings),
     ordem_reescrita.csv (nivel 0 = folha; funcoes recursivas/ciclos marcadas pelo SCC).
  5  data\: CSV de todos os itens de .data/.rdata/.bss (endereco, tamanho, nome, valor,
     xrefs, funcoes que usam), .bin cru de cada segmento, constantes float/double,
     TABELAS CANDIDATAS de doubles (heuristica) e tabelas.c/globais.c com os valores
     iniciais em C (17 digitos significativos).
  6  Falhas do decompilador: o IDA reanalisa a funcao e tenta de novo (retry); o que continua
     falhando vai para falhas_priorizadas.csv (ordenada por impacto: exportada, exports
     afetados, dependentes, tamanho), falhas_resumo.txt (histograma por categoria + o que
     tentar) e decompile_failures.csv. O .c da funcao traz motivo, categoria, sugestao,
     impacto, EXEMPLOS DE CHAMADA (linhas dos chamadores que mostram os argumentos) e
     DISASSEMBLY ANOTADO (blocos com preds/succs, chamadas/imports resolvidos, strings e
     constantes double/float decodificadas); tambem em asm\<funcao>.asm.
  7  disasm_completo.asm (idc.gen_file OFILE_ASM).
  8  RTTI MSVC (COL, hierarquia de bases) e vtables Itanium/MSVC -> classes_rtti.json
     e classes_skeleton.hpp.
  9  dependencias_dlls.py: imports, delay-load, forwarders e strings "*.dll" -> grafo,
     ordem_build.txt (dependencias primeiro; ciclos agrupados) e runtimes de terceiros.
 10  projeto\ (src, include, .def, build.bat com compilador sugerido).
 11  comparar_dlls.py PASTA_ORIGINAL RECOMPILADA.dll --ida "...\ida.exe"
     reanalisa com o mesmo pipeline e compara exports, imports, secoes, numero de
     funcoes, tamanho de codigo, tamanho das exportadas e chamadas externas. Lista os
     dois .i64 para voce abrir no BinDiff.
 12  teste_diferencial.py (ver abaixo).
 13  Timeout por DLL: o IDA e encerrado com taskkill /T; antes disso o script entra num
     prazo "suave" (70% do timeout) em que para de decompilar e fecha as saidas, de
     modo que normalmente voce recebe resultado parcial em vez de nada.
 14  Retomada: ANALISE_CONCLUIDA.json guarda sha256+versao; DLL igual ja analisada
     (ok/parcial/gerenciada/nao_pe) e pulada. erro/timeout sao refeitos
     (--pular-falhas desliga). --force refaz tudo.
 15  resumo.csv/json.

Teste diferencial (item 12)
---------------------------
  1. projeto\tests\casos_teste.json ja vem com um MODELO gerado dos prototipos do IDA
     (confira tipos, "n" = tamanho dos arrays, "dir" = in/out/inout, defina casos).
  2. Compile a DLL:   projeto\build.bat
  3. Rode:            projeto\tests\executar_teste.bat
     ou: python teste_diferencial.py executar casos_teste.json --saida relatorio
  Detalhes:
   * Cada DLL roda num processo separado: o Windows nao carrega duas DLLs com o mesmo
     nome no mesmo processo, e STOP/erro severo do runtime Fortran ou Access Violation
     so derrubam o worker (vira "crash" no relatorio; a execucao continua).
   * "modo":"ref" = ponteiro (padrao Fortran), "val" = por valor; "n" = tamanho do array;
     tipo "char" com "len_oculto": true acrescenta o tamanho oculto de CHARACTER.
   * Tolerancia: rtol/atol (padrao 1e-9 / 1e-12) e opcional "ulps"; NaN==NaN, inf==inf.
   * "fuzz": {"n":100,"seed":1,"faixas":{"T":[200,1500]},"escala":{"P":"log"},
              "normalizar":["x"]}   (normalizar = fracoes que somam 1)
   * O Python precisa ter o mesmo numero de bits da DLL (32 ou 64).
   * Se a DLL depende de runtimes (Intel/MinGW): "dll_dirs": ["C:\\...\\bin"].
   * Retornos CHARACTER/COMPLEX de Fortran tem convencao propria: nao cobertos.

Fluxo sugerido de recompilacao
------------------------------
  1. Leia resumo.csv e ordem_build.txt (qual DLL primeiro).
  2. Em cada DLL: compiler_info.txt -> compilador/flags; projeto\LEIA-ME_PROJETO.txt.
  3. Reescreva seguindo ordem_reescrita.csv (folhas primeiro). Tabelas de coeficientes:
     data\tabelas_candidatas.csv e projeto\dados\tabelas.c.
  4. projeto\build.bat check acompanha quantos .c compilam; build.bat liga a DLL com o
     mesmo .def (um LNK2001 = export ainda sem implementacao).
  5. teste_diferencial.py a cada funcao; no fim, comparar_dlls.py + BinDiff.
  Dica numerica: se o binario usa x87 (32 bits), precisao estendida de 80 bits nos
  intermediarios pode ser a diferenca entre os numeros; /arch:IA32 e /fp:strict.

Melhorias extras incluidas (alem dos 15 itens)
----------------------------------------------
  * defs.h do IDA (plugins\defs.h) copiado para projeto\include\ (sem ele o pseudocodigo
    nao compila: _DWORD, LODWORD, BYTE1...). Se nao achar, grava um defs.h minimo.
  * funcoes.h (prototipos de todas as funcoes, folhas primeiro) e tipos.h (structs/enums
    locais do IDA) incluidos em cada .c.
  * Simbolos mangled/invalidos em C renomeados no banco (renomeacoes.csv).
  * Deteccao de arquivo empacotado (UPX/entropia) e Rich Header/POGO (LTCG) no PE.
  * Funcoes tomadas por endereco (callbacks/vtables) entram no grafo; chamadas
    indiretas contadas por funcao.
  * Fases do IDA isoladas: se uma falha, grava erro_fase_<nome>.txt e as demais seguem.
  * --jobs para paralelizar; idat.exe (console) usado no lugar do ida.exe se existir.

Requisitos
----------
  * pefile (o .bat instala se faltar).
  * IDAPython configurado com idapyswitch (o IDA usa o Python dele, nao o do BAT; so
    biblioteca padrao e usada dentro do IDA).
  * Hex-Rays para a arquitetura da DLL.

Limites / o que NAO foi verificado
----------------------------------
  * Nao havia IDA nem Windows no ambiente de desenvolvimento. analisar_ida.py foi
    exercitado contra um IDA SIMULADO (tests\mock_ida.py); chamadas como tinfo._print,
    get_numbered_type, idc.gen_file, print_insn_mnem e os campos de FUNC_* podem
    precisar de ajuste fino no IDA 9.1 real. Cada fase falha isoladamente
    (erro_fase_*.txt) para facilitar esse ajuste. Os .bat gerados (build.bat etc.)
    tambem nao foram executados.
  * Classificacao user/lib, tabelas candidatas, flags sugeridas e "familia" do
    compilador sao HEURISTICAS: indicios, nao garantia.
  * Rich Header: sao mostrados prodid/build/count; o mapeamento para versao do VS usa
    a versao do linker do PE (mais confiavel que tabelas de prodid).
  * globais.c define cada global separadamente: se o codigo original faz aritmetica de
    ponteiro entre itens vizinhos, use data\<segmento>.bin como referencia.
  * O pseudocodigo Hex-Rays nao e o fonte original e raramente compila sem ajustes.
  * Use apenas em software que voce tem direito de analisar/recompilar.

Testes (fora do Windows/IDA)
----------------------------
  python tests/test_analisar_ida.py   executa analisar_ida.py contra o IDA simulado
  python tests/test_pipeline.py       lote completo: nativa/mista/gerenciada/invalida,
                                      timeout, retomada, --only
  (precisam de pefile e de um shell POSIX para tests/fake_ida.sh)
