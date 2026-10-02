@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================
REM RECUPERACAO DE DLLs - IDA PRO 9.1 + dotPeek      (Versao 5)
REM   Nativas  -> IDA/Hex-Rays     Mistas -> IDA (parte nativa) + dotPeek
REM   Gerenciadas (.NET IL-only) -> dotPeek (nao passam pelo IDA)
REM Argumentos extras sao repassados ao orquestrar.py, por exemplo:
REM   analisar_dlls.bat --force            refaz tudo (ignora o que ja foi analisado)
REM   analisar_dlls.bat --only ze1,ze2     so essas DLLs
REM   analisar_dlls.bat --jobs 3           3 IDAs em paralelo
REM   analisar_dlls.bat --timeout 7200     timeout por DLL (segundos)
REM   analisar_dlls.bat --pular-falhas     na retomada, nao repete erro/timeout
REM   analisar_dlls.bat --decompile-lib    tambem decompila funcoes de biblioteca
REM ============================================================

set "IDA=C:\Program Files\IDA Professional 9.1\ida.exe"
set "PYTHON=C:\Users\taver\AppData\Local\Python\pythoncore-3.14-64\python.exe"
set "DLL_DIR=D:\DLLs\ze"
set "OUTPUT_DIR=%DLL_DIR%\_REVERSE"

REM Tempo maximo do IDA por DLL, em segundos (o IDA e encerrado e o lote continua)
set "TIMEOUT_SEG=3600"
REM Quantos IDAs ao mesmo tempo (1 = sequencial)
set "JOBS=1"
REM Caminho do dotPeek64.exe (opcional; se vazio o script tenta achar sozinho)
set "DOTPEEK="

set "PYTHONUTF8=1"
set "SCRIPT_DIR=%~dp0"

REM Os .py podem estar na mesma pasta do .bat ou em ida_scripts\
set "SCRIPTS=%SCRIPT_DIR%"
if exist "%SCRIPT_DIR%ida_scripts\orquestrar.py" set "SCRIPTS=%SCRIPT_DIR%ida_scripts\"

if not exist "%IDA%" (
    echo ERRO: nao encontrei o IDA:
    echo %IDA%
    pause
    exit /b 1
)
if not exist "%PYTHON%" (
    echo ERRO: nao encontrei o Python:
    echo %PYTHON%
    pause
    exit /b 1
)
if not exist "%DLL_DIR%" (
    echo ERRO: nao encontrei a pasta das DLLs:
    echo %DLL_DIR%
    pause
    exit /b 1
)
for %%S in (orquestrar classificar_dll analisar_ida analise_comum gerar_projeto dependencias_dlls teste_diferencial comparar_dlls) do (
    if not exist "%SCRIPTS%%%S.py" (
        echo ERRO: %%S.py nao encontrado em %SCRIPTS%
        pause
        exit /b 1
    )
)

"%PYTHON%" -c "import pefile" >nul 2>&1
if errorlevel 1 (
    echo Instalando pefile...
    "%PYTHON%" -m pip install pefile
    if errorlevel 1 (
        echo ERRO: nao foi possivel instalar pefile.
        pause
        exit /b 1
    )
)

set "EXTRA="
if defined DOTPEEK set EXTRA=!EXTRA! --dotpeek "%DOTPEEK%"

echo.
echo ============================================================
echo RECUPERACAO DE DLLs - IDA PRO 9.1 (versao 5)
echo ============================================================
echo IDA      : %IDA%
echo Python   : %PYTHON%
echo DLLs     : %DLL_DIR%
echo Saida    : %OUTPUT_DIR%
echo Scripts  : %SCRIPTS%
echo Timeout  : %TIMEOUT_SEG% s por DLL   Jobs: %JOBS%
echo ============================================================
echo.

"%PYTHON%" "%SCRIPTS%orquestrar.py" --ida "%IDA%" --dlls "%DLL_DIR%" --out "%OUTPUT_DIR%" --timeout %TIMEOUT_SEG% --jobs %JOBS% !EXTRA! %*
set "RC=!ERRORLEVEL!"

echo.
echo ============================================================
echo Codigo de saida: !RC!   (0 = tudo certo, 1 = alguma DLL com erro/timeout)
echo Resumo (CSV)   : %OUTPUT_DIR%\resumo.csv
echo Ordem de build : %OUTPUT_DIR%\ordem_build.txt
if exist "%OUTPUT_DIR%\_GERENCIADAS\abrir_no_dotpeek.bat" echo DLLs .NET      : %OUTPUT_DIR%\_GERENCIADAS\abrir_no_dotpeek.bat
echo ============================================================
echo.

pause
endlocal & exit /b %RC%
