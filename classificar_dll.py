# -*- coding: utf-8 -*-
"""
classificar_dll.py - analise estatica do PE (roda fora do IDA, so precisa de pefile).

Uso:  python classificar_dll.py dll [pasta_saida]

Gera em pasta_saida:
  SUMMARY.txt, architecture.txt, classification.txt, classification.json
  exports_pe.json, imports_pe.txt, imports_pe.json, clr_info.json
  compiler_info.json / compiler_info.txt  (linker, Rich Header, timestamp, PDB,
                                           strings de compilador, runtime, flags sugeridas)
  projeto\\NOME.def                        (mesma interface: nomes + ordinais)

Tipo (classification.json -> "tipo"):
  nativa | mista | gerenciada | invalida
"""
import datetime
import hashlib
import os
import re
import struct
import sys

try:
    import pefile
except ImportError:
    print("ERRO: pefile nao instalado.")
    sys.exit(2)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analise_comum as ac  # noqa: E402

CLR_FLAGS = {
    0x1: "ILONLY", 0x2: "32BITREQUIRED", 0x4: "IL_LIBRARY (ReadyToRun)",
    0x8: "STRONGNAMESIGNED", 0x10: "NATIVE_ENTRYPOINT", 0x10000: "TRACKDEBUGDATA",
    0x20000: "32BITPREFERRED",
}

DLL_CHARS = {
    0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE", 0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT", 0x0200: "NO_ISOLATION", 0x0400: "NO_SEH", 0x0800: "NO_BIND",
    0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER", 0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

DEBUG_TIPOS = {
    1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP",
    9: "BORLAND", 10: "RESERVED10", 11: "CLSID", 12: "VC_FEATURE", 13: "POGO",
    14: "ILTCG", 15: "MPX", 16: "REPRO", 20: "EX_DLLCHARACTERISTICS",
}

# marcador -> (familia, descricao). Procurado nos bytes crus do arquivo.
MARCADORES = [
    (rb"Intel\(R\) (?:Visual )?Fortran[^\x00]{0,80}", "intel_fortran", "string Intel Fortran"),
    (rb"Intel\(R\) oneAPI[^\x00]{0,80}", "intel_oneapi", "string Intel oneAPI"),
    (rb"Intel\(R\) C\+\+[^\x00]{0,80}", "intel_cpp", "string Intel C++"),
    (rb"forrtl: [a-z]+", "intel_fortran", "mensagem do runtime Intel Fortran (forrtl)"),
    (rb"Compaq Visual Fortran[^\x00]{0,60}", "compaq_fortran", "Compaq Visual Fortran"),
    (rb"DIGITAL Visual Fortran[^\x00]{0,60}", "compaq_fortran", "Digital Visual Fortran"),
    (rb"GNU Fortran[^\x00]{0,80}", "gnu_fortran", "string GNU Fortran"),
    (rb"Fortran runtime error", "gnu_fortran", "mensagem do runtime gfortran"),
    (rb"GCC: \([^\x00]{1,80}", "gcc", "comentario GCC (.comment)"),
    (rb"Mingw-w64 runtime failure", "gcc", "runtime MinGW-w64"),
    (rb"clang version [^\x00]{1,60}", "clang", "string clang"),
    (rb"Microsoft \(R\) Optimizing Compiler[^\x00]{0,40}", "msvc", "string MSVC"),
    (rb"Microsoft Visual C\+\+ Runtime Library", "msvc", "mensagem do CRT MSVC"),
    (rb"PGI[^\x00]{0,40}Fortran|NVIDIA Fortran[^\x00]{0,40}|pgf90|pgfortran", "pgi_fortran", "PGI/NVIDIA Fortran"),
    (rb"Lahey[^\x00]{0,40}Fortran[^\x00]{0,30}", "lahey_fortran", "Lahey Fortran"),
    (rb"Salford[^\x00]{0,40}", "salford_fortran", "Salford/Silverfrost Fortran"),
    (rb"Open Watcom[^\x00]{0,40}|WATCOM[^\x00]{0,40}", "watcom", "Watcom"),
    (rb"Borland C\+\+[^\x00]{0,40}|Embarcadero[^\x00]{0,40}", "borland", "Borland/Embarcadero"),
    (rb"rustc version [^\x00]{1,40}", "rust", "rustc"),
    (rb"Go buildinf:", "go", "binario Go"),
    (rb"UPX!", "packer_upx", "packer UPX"),
]

# import -> (runtime, geracao de toolchain)
CRT_MAP = {
    "msvcrt.dll": ("MSVCRT (VC6 / MinGW / sistema)", "VC6 ou MinGW"),
    "msvcr70.dll": ("MSVCR70", "VS2002"), "msvcr71.dll": ("MSVCR71", "VS2003"),
    "msvcr80.dll": ("MSVCR80", "VS2005"), "msvcr90.dll": ("MSVCR90", "VS2008"),
    "msvcr100.dll": ("MSVCR100", "VS2010"), "msvcr110.dll": ("MSVCR110", "VS2012"),
    "msvcr120.dll": ("MSVCR120", "VS2013"),
    "vcruntime140.dll": ("VCRUNTIME140 + UCRT", "VS2015-2022"),
    "vcruntime140_1.dll": ("VCRUNTIME140_1 + UCRT", "VS2019-2022"),
    "ucrtbase.dll": ("UCRT", "VS2015-2022"),
}

RUNTIMES = [
    (("libifcoremd", "libifcore", "libifport", "libmmd", "libirc", "svml_disp"), "Intel Fortran/C runtime"),
    (("libiomp5md",), "Intel OpenMP"),
    (("mkl_", "libmkl"), "Intel MKL"),
    (("libgfortran",), "GNU Fortran runtime"),
    (("libquadmath",), "libquadmath"),
    (("libgomp",), "GNU OpenMP"),
    (("libstdc++",), "libstdc++ (MinGW)"),
    (("libgcc_s",), "libgcc (MinGW)"),
    (("libwinpthread",), "winpthreads (MinGW)"),
    (("msvcp", "vcruntime", "ucrtbase", "api-ms-win-crt", "msvcr"), "Microsoft C/C++ runtime"),
    (("vcomp",), "MSVC OpenMP"),
    (("mscoree",), ".NET CLR"),
    (("openblas", "libopenblas"), "OpenBLAS"),
    (("lapack", "blas"), "BLAS/LAPACK"),
]


def dec(x):
    return x.decode("utf-8", errors="replace") if isinstance(x, bytes) else str(x)


def architecture(pe):
    m = pe.FILE_HEADER.Machine
    return {
        0x8664: "x64 / AMD64", 0x014C: "x86 / i386", 0xAA64: "ARM64",
        0x01C4: "ARM", 0xA641: "ARM64EC", 0x0200: "IA64",
    }.get(m, f"Unknown (0x{m:04X})")


# ---------------------------------------------------------------------------
# CLR
# ---------------------------------------------------------------------------
def clr_info(pe):
    try:
        idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        if not d.VirtualAddress:
            return None
        data = pe.get_data(d.VirtualAddress, min(d.Size, 72))
        if len(data) < 20:
            return {"present": True}
        # IMAGE_COR20_HEADER: cb, major, minor, MetaData(RVA,Size), Flags
        cb, maj, minr, mdr, mds, flags = struct.unpack("<IHHIII", data[:20])
        info = {
            "present": True,
            "runtime_version": f"{maj}.{minr}",
            "flags": flags,
            "raw_flags": f"0x{flags:08X}",
            "flags_nomes": [n for b, n in CLR_FLAGS.items() if flags & b],
            "il_only": bool(flags & 0x1),
            "il_library_r2r": bool(flags & 0x4),
            "native_entry_point": bool(flags & 0x10),
            "metadata_rva": f"0x{mdr:08X}",
            "metadata_size": mds,
        }
        return info
    except Exception:
        return {"present": True}


def decidir_tipo(clr, tem_exports):
    """Retorna (tipo, texto_classificacao, observacao)."""
    if not clr:
        return "nativa", "Native PE", ""
    if clr.get("il_only") is False and not clr.get("il_library_r2r"):
        return ("mista",
                "CLR + native code / possivel C++/CLI mixed-mode",
                "Parte nativa -> IDA/Hex-Rays. Parte gerenciada -> dotPeek.")
    obs = ""
    if clr.get("il_library_r2r"):
        obs = "ReadyToRun: o IL continua presente; dotPeek funciona."
    elif tem_exports:
        obs = "IL-only com exports (possivel UnmanagedExports/DllExport): conferir."
    return "gerenciada", "Managed .NET / CLR", obs


# ---------------------------------------------------------------------------
# Exports / imports
# ---------------------------------------------------------------------------
def exports(pe):
    out = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            fwd = dec(s.forwarder) if getattr(s, "forwarder", None) else ""
            eh_dado = False
            secao = ""
            if not fwd:
                sec = pe.get_section_by_rva(s.address)
                if sec is not None:
                    secao = dec(sec.Name).rstrip("\x00")
                    eh_dado = not (sec.Characteristics & 0x20000000)
            out.append({
                "ordinal": s.ordinal,
                "rva": f"0x{s.address:08X}",
                "name": dec(s.name) if s.name else "",
                "forwarder": fwd,
                "data": eh_dado,
                "section": secao,
            })
    return out


def imports(pe):
    out = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            item = {"dll": dec(e.dll), "delay": False, "functions": []}
            for i in e.imports:
                item["functions"].append({
                    "address": f"0x{(i.address or 0):016X}",
                    "name": dec(i.name) if i.name else "",
                    "ordinal": i.ordinal,
                })
            out.append(item)
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            item = {"dll": dec(e.dll), "delay": True, "functions": []}
            for i in e.imports:
                item["functions"].append({
                    "address": f"0x{(i.address or 0):016X}",
                    "name": dec(i.name) if i.name else "",
                    "ordinal": i.ordinal,
                })
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Compilador / flags
# ---------------------------------------------------------------------------
def rich_header(dados):
    """Decodifica o Rich Header (None se ausente). Entradas: prodid, build, count."""
    try:
        fim = dados.find(b"Rich", 0x40, 0x400)
        if fim < 0:
            return None
        chave = struct.unpack_from("<I", dados, fim + 4)[0]
        ini = -1
        pos = fim - 4
        while pos >= 0x40:
            if struct.unpack_from("<I", dados, pos)[0] ^ chave == 0x536E6144:  # "DanS"
                ini = pos
                break
            pos -= 4
        if ini < 0:
            return None
        entradas = []
        p = ini + 16   # pula DanS + 3 dwords de padding
        while p < fim:
            comp, cont = struct.unpack_from("<II", dados, p)
            comp ^= chave
            cont ^= chave
            if comp:
                entradas.append({"prodid": comp >> 16, "build": comp & 0xFFFF,
                                 "count": cont, "comp_id": f"0x{comp:08X}"})
            p += 8
        return {"xor_key": f"0x{chave:08X}", "entradas": entradas}
    except Exception:
        return None


def toolset_pelo_linker(maj, mini):
    if maj == 2:
        return "GNU ld (binutils) -> MinGW/GCC/gfortran"
    mapa = {(5, 0): "VC5", (6, 0): "VC6", (7, 0): "VS2002", (7, 10): "VS2003",
            (8, 0): "VS2005", (9, 0): "VS2008", (10, 0): "VS2010", (11, 0): "VS2012",
            (12, 0): "VS2013", (14, 0): "VS2015"}
    if (maj, mini) in mapa:
        return mapa[(maj, mini)]
    if maj == 14:
        if 10 <= mini < 20:
            return "VS2017 (14.1x)"
        if 20 <= mini < 30:
            return "VS2019 (14.2x)"
        if mini >= 30:
            return "VS2022 (14.3x+)"
    return f"linker {maj}.{mini} (desconhecido)"


def varrer_strings_compilador(dados):
    achados = []
    for pat, familia, desc in MARCADORES:
        rx = re.compile(rb"[\x20-\x7e]{0,60}" + pat, re.I if familia != "gcc" else 0)
        vistos = set()
        for m in rx.finditer(dados):
            txt = m.group(0).decode("latin-1").strip()
            if txt in vistos:
                continue
            vistos.add(txt)
            achados.append({"familia": familia, "descricao": desc,
                            "texto": txt[:200], "offset": f"0x{m.start():X}"})
            if len(vistos) >= 4:
                break
    return achados


def version_info(pe):
    info = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for ent in (fi if isinstance(fi, list) else [fi]):
                for st in getattr(ent, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        info[dec(k)] = dec(v)
    except Exception:
        pass
    return info


def pdb_info(pe, dados):
    """Caminho do PDB + GUID/Age e lista de tipos de debug (POGO/ILTCG/REPRO)."""
    res = {"pdb_path": None, "guid": None, "age": None, "tipos_debug": []}
    for ent in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        st = ent.struct
        res["tipos_debug"].append(DEBUG_TIPOS.get(st.Type, f"tipo_{st.Type}"))
        if st.Type == 2 and st.SizeOfData >= 24:
            blob = dados[st.PointerToRawData: st.PointerToRawData + st.SizeOfData]
            if blob[:4] == b"RSDS":
                d1, d2, d3 = struct.unpack_from("<IHH", blob, 4)
                d4 = blob[12:20].hex()
                res["guid"] = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4].upper()}-{d4[4:].upper()}"
                res["age"] = struct.unpack_from("<I", blob, 20)[0]
                res["pdb_path"] = blob[24:].split(b"\x00")[0].decode("utf-8", "replace")
            elif blob[:4] == b"NB10":
                res["pdb_path"] = blob[16:].split(b"\x00")[0].decode("utf-8", "replace")
    return res


def detectar_compilador(pe, dados, im):
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    maj, mini = oh.MajorLinkerVersion, oh.MinorLinkerVersion
    ts = fh.TimeDateStamp
    try:
        data_ts = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    except Exception:
        data_ts = None
    pdb = pdb_info(pe, dados)
    repro = "REPRO" in pdb["tipos_debug"]
    rich = rich_header(dados)
    strings = varrer_strings_compilador(dados)
    ver = version_info(pe)

    nomes_imp = [x["dll"].lower() for x in im]
    todos = " ".join(nomes_imp)
    runtimes = []
    for chaves, nome in RUNTIMES:
        if any(c in todos for c in chaves):
            runtimes.append(nome)
    crt = [CRT_MAP[n] for n in nomes_imp if n in CRT_MAP]
    for n in nomes_imp:
        if n.startswith("api-ms-win-crt"):
            crt.append(("UCRT (api-ms-win-crt)", "VS2015-2022"))
            break
    nomes_funcs = " ".join(f["name"] for x in im for f in x["functions"])
    usa_for = bool(re.search(r"\b_?for_(write|read|open|close|alloc|stop)", nomes_funcs))

    # --- familia ---
    familias = {s["familia"] for s in strings}
    if any(c in todos for c in ("libifcore", "libifport", "libmmd")) or usa_for:
        familias.add("intel_fortran")
    if "libgfortran" in todos:
        familias.add("gnu_fortran")
    if maj == 2 or "libgcc_s" in todos or "libstdc++" in todos:
        familias.add("gcc")

    toolset = toolset_pelo_linker(maj, mini)
    arq64 = fh.Machine in (0x8664, 0xAA64, 0xA641)
    flags_link = []
    flags_link.append("/MACHINE:" + {0x8664: "X64", 0x14C: "X86", 0xAA64: "ARM64"}.get(fh.Machine, "X64"))
    flags_link.append("/DLL")
    if oh.DllCharacteristics & 0x40:
        flags_link.append("/DYNAMICBASE")
    else:
        flags_link.append("/DYNAMICBASE:NO")
    if oh.DllCharacteristics & 0x100:
        flags_link.append("/NXCOMPAT")
    if oh.DllCharacteristics & 0x4000:
        flags_link.append("/GUARD:CF")
    if oh.DllCharacteristics & 0x20 and arq64:
        flags_link.append("/HIGHENTROPYVA")
    if (fh.Characteristics & 0x20) and not arq64:
        flags_link.append("/LARGEADDRESSAWARE")
    flags_link.append(f"/BASE:0x{oh.ImageBase:X}")
    flags_link.append(f"/SUBSYSTEM:WINDOWS,{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion:02d}")
    flags_link.append(f"/STACK:{oh.SizeOfStackReserve},{oh.SizeOfStackCommit}")
    if oh.MajorImageVersion or oh.MinorImageVersion:
        flags_link.append(f"/VERSION:{oh.MajorImageVersion}.{oh.MinorImageVersion}")

    # --- recomendacao ---
    rec = {"familia": "desconhecida", "compilador": "MSVC (cl.exe)",
           "flags_compilador": [], "flags_link": flags_link, "observacoes": []}
    if familias & {"intel_fortran", "intel_oneapi"}:
        rec["familia"] = "intel_fortran"
        rec["compilador"] = "Intel Fortran (ifort classico ou ifx) + link.exe do " + toolset
        estatico = not any("libifcore" in n for n in nomes_imp)
        rec["flags_compilador"] = ["/dll", "/libs:static" if estatico else "/libs:dll",
                                   "/threads", "/O2", "/fp:source", "/Qprec-div", "/Qftz-"]
        rec["observacoes"].append(
            "Flags numericas (/fp:source, /Qprec-div, /Qftz-) sao palpite conservador "
            "para reproduzir numeros; ajuste apos o teste diferencial.")
        if estatico:
            rec["observacoes"].append("Sem import de libifcore: runtime Fortran provavelmente ligado estaticamente.")
    elif familias & {"gnu_fortran", "gcc", "clang"} or maj == 2:
        rec["familia"] = "gnu_fortran" if "gnu_fortran" in familias else ("clang" if "clang" in familias else "gcc")
        rec["compilador"] = "MinGW-w64 gcc/gfortran" + (" (clang)" if "clang" in familias else "")
        rec["flags_compilador"] = ["-shared", "-O2", "-ffp-contract=off", "-fno-fast-math"]
        rec["flags_link"] = ["-Wl,--kill-at"] if not arq64 else []
    elif "compaq_fortran" in familias:
        rec["familia"] = "compaq_fortran"
        rec["compilador"] = "Compaq/Digital Visual Fortran 6.x (legado) - preferir Intel Fortran moderno"
    elif "msvc" in familias or toolset.startswith("VS") or toolset.startswith("VC"):
        rec["familia"] = "msvc"
        rec["compilador"] = "MSVC cl.exe, toolset " + toolset
        rec["flags_compilador"] = ["/LD", "/O2", "/fp:strict", "/MD" if crt else "/MT"]
    for p in ("packer_upx",):
        if p in familias:
            rec["observacoes"].append("Arquivo empacotado (UPX): desempacote antes (upx -d) para o IDA enxergar o codigo.")
    if arq64 is False:
        rec["observacoes"].append("x86: exports __stdcall aparecem decorados (_Nome@N); use /KILLAT ou .def.")

    # --- secoes / empacotamento ---
    secoes = []
    suspeita_pack = False
    for s in pe.sections:
        nome = dec(s.Name).rstrip("\x00")
        ent = s.get_entropy()
        secoes.append({
            "nome": nome, "vsize": s.Misc_VirtualSize, "rawsize": s.SizeOfRawData,
            "rva": f"0x{s.VirtualAddress:08X}", "entropia": round(ent, 2),
            "caracteristicas": f"0x{s.Characteristics:08X}",
            "exec": bool(s.Characteristics & 0x20000000),
        })
        if (nome.upper().startswith(("UPX", ".VMP", ".THEMIDA", ".ASPACK", ".ENIGMA", ".PETITE"))
                or (s.Characteristics & 0x20000000 and ent > 7.3)):
            suspeita_pack = True
    if suspeita_pack:
        rec["observacoes"].append("Secao executavel com entropia alta / nome de packer: possivel empacotamento.")

    obs_ts = ""
    if repro:
        obs_ts = "Build reprodutivel (/Brepro): o timestamp e um hash, nao uma data."
    elif ts and (ts < 788918400 or ts > datetime.datetime.now().timestamp() + 86400):
        obs_ts = "Timestamp implausivel (fora de 1995..hoje): provavel hash/valor sintetico."

    pogo = any(t in pdb["tipos_debug"] for t in ("POGO", "ILTCG"))
    if pogo:
        rec["observacoes"].append("Debug POGO/ILTCG: binario com LTCG/PGO - funcoes podem estar fundidas/inlinadas.")

    return {
        "linker_version": f"{maj}.{mini}",
        "toolset_pelo_linker": toolset,
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "subsystem_version": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}",
        "image_version": f"{oh.MajorImageVersion}.{oh.MinorImageVersion}",
        "timestamp": ts,
        "timestamp_utc": data_ts,
        "timestamp_observacao": obs_ts,
        "checksum": f"0x{oh.CheckSum:08X}",
        "image_base": f"0x{oh.ImageBase:X}",
        "entry_point_rva": f"0x{oh.AddressOfEntryPoint:08X}",
        "size_of_image": oh.SizeOfImage,
        "section_alignment": oh.SectionAlignment,
        "file_alignment": oh.FileAlignment,
        "stack_reserve": oh.SizeOfStackReserve,
        "heap_reserve": oh.SizeOfHeapReserve,
        "dll_characteristics": [n for b, n in DLL_CHARS.items() if oh.DllCharacteristics & b],
        "pdb": pdb,
        "rich_header": rich,
        "strings_compilador": strings,
        "version_info": ver,
        "runtimes": runtimes,
        "crt": [{"runtime": a, "geracao": b} for a, b in crt],
        "familias_detectadas": sorted(familias),
        "tem_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
        "overlay_bytes": max(0, len(dados) - (pe.get_overlay_data_start_offset() or len(dados))),
        "secoes": secoes,
        "recomendacao": rec,
    }


def texto_compilador(ci):
    L = ["COMPILADOR / TOOLCHAIN (indicios - nao e garantia)",
         "=" * 52,
         f"Linker           : {ci['linker_version']}  ->  {ci['toolset_pelo_linker']}",
         f"Timestamp        : {ci['timestamp_utc']} (raw={ci['timestamp']}) {ci['timestamp_observacao']}",
         f"PDB              : {ci['pdb']['pdb_path']}  GUID={ci['pdb']['guid']} age={ci['pdb']['age']}",
         f"Debug dir        : {', '.join(ci['pdb']['tipos_debug']) or '-'}",
         f"OS/Subsystem     : {ci['os_version']} / {ci['subsystem_version']}",
         f"ImageBase        : {ci['image_base']}   Entry RVA: {ci['entry_point_rva']}",
         f"DllCharacteristic: {', '.join(ci['dll_characteristics']) or '-'}",
         f"CRT              : {', '.join(c['runtime'] + ' (' + c['geracao'] + ')' for c in ci['crt']) or '-'}",
         f"Runtimes         : {', '.join(ci['runtimes']) or '-'}",
         f"Familias         : {', '.join(ci['familias_detectadas']) or '-'}", ""]
    if ci["version_info"]:
        L.append("VersionInfo:")
        for k, v in ci["version_info"].items():
            L.append(f"  {k}: {v}")
        L.append("")
    if ci["strings_compilador"]:
        L.append("Strings de compilador:")
        for s in ci["strings_compilador"]:
            L.append(f"  [{s['familia']}] {s['offset']}: {s['texto']}")
        L.append("")
    rh = ci["rich_header"]
    if rh:
        L.append(f"Rich Header (xor={rh['xor_key']}): prodid / build / count")
        for e in rh["entradas"]:
            L.append(f"  prodid=0x{e['prodid']:04X} build={e['build']:5d} count={e['count']}")
        L.append("")
    r = ci["recomendacao"]
    L += ["RECOMENDACAO",
          f"  Familia    : {r['familia']}",
          f"  Compilador : {r['compilador']}",
          f"  Flags comp.: {' '.join(r['flags_compilador'])}",
          f"  Flags link : {' '.join(r['flags_link'])}"]
    for o in r["observacoes"]:
        L.append(f"  * {o}")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------
def analisar(dll, out):
    """Executa toda a classificacao. Retorna dict (res['erro'] preenchido se falhar)."""
    dll = os.path.abspath(dll)
    os.makedirs(out, exist_ok=True)
    res = {"arquivo": dll, "nome": os.path.splitext(os.path.basename(dll))[0], "erro": None}
    try:
        with open(dll, "rb") as f:
            dados = f.read()
        res["sha256"] = hashlib.sha256(dados).hexdigest()
        res["tamanho"] = len(dados)
        pe = pefile.PE(data=dados)
    except Exception as e:
        res.update({"tipo": "invalida", "erro": f"ERRO ao abrir PE: {e}"})
        with open(os.path.join(out, "SUMMARY.txt"), "w", encoding="utf-8") as f:
            f.write(f"Arquivo: {dll}\nERRO ao abrir PE: {e}\n")
        ac.gravar_json(os.path.join(out, "classification.json"), {"tipo": "invalida", "erro": str(e)})
        return res

    arch = architecture(pe)
    clr = clr_info(pe)
    ex = exports(pe)
    im = imports(pe)
    tipo, classificacao, obs = decidir_tipo(clr, bool(ex))
    try:
        ci = detectar_compilador(pe, dados, im)
    except Exception as e:  # nunca derruba a classificacao
        ci = None
        res["aviso_compilador"] = f"{type(e).__name__}: {e}"
    res["imphash"] = pe.get_imphash() if im else ""
    pe.close()

    texto = " ".join([x["dll"].lower() for x in im] +
                     [f["name"].lower() for x in im for f in x["functions"]])
    hints = []
    if any(x in texto for x in ("libifcore", "libifport", "libmmd", "ifcore")):
        hints.append("Intel Fortran runtime")
    if "libgfortran" in texto:
        hints.append("GNU Fortran runtime")
    if "libquadmath" in texto:
        hints.append("GNU Fortran / libquadmath")
    if any(x in texto for x in ("vcruntime", "msvcp", "ucrtbase", "msvcr")):
        hints.append("Microsoft C/C++ runtime")
    if "mscoree" in texto:
        hints.append(".NET CLR")

    res.update({
        "arquitetura": arch, "tipo": tipo, "classificacao": classificacao,
        "observacao": obs, "clr": clr, "n_exports": len(ex), "n_imports_dlls": len(im),
        "dlls_importadas": sorted({x["dll"] for x in im}, key=str.lower),
        "indicios_runtime": hints,
        "compilador": (ci or {}).get("recomendacao", {}).get("compilador", ""),
        "familia": (ci or {}).get("recomendacao", {}).get("familia", ""),
        "toolset": (ci or {}).get("toolset_pelo_linker", ""),
    })
    if tipo == "gerenciada":     # linker/Rich Header nao dizem nada sobre o compilador de IL
        res.update({"compilador": ".NET (IL) - usar dotPeek", "familia": "dotnet", "toolset": ""})

    P = lambda n: os.path.join(out, n)  # noqa: E731
    with open(P("SUMMARY.txt"), "w", encoding="utf-8") as f:
        f.write(f"Arquivo: {dll}\n")
        f.write(f"SHA256: {res['sha256']}\n")
        f.write(f"Arquitetura: {arch}\n")
        f.write(f"Classificacao: {classificacao}\n")
        f.write(f"Tipo: {tipo}\n")
        f.write(f"CLR: {'SIM' if clr else 'NAO'}\n")
        f.write(f"Exports: {len(ex)}\n")
        f.write(f"DLLs importadas: {len(im)}\n")
        if ci:
            f.write(f"Toolset (linker): {ci['toolset_pelo_linker']}\n")
            f.write(f"Compilador sugerido: {ci['recomendacao']['compilador']}\n")
        if obs:
            f.write(f"Obs: {obs}\n")
        f.write("\nIndicios de runtime:\n")
        f.write("\n".join("  - " + x for x in hints) if hints else "  - nenhum indicio conhecido")
        f.write("\n")
    with open(P("architecture.txt"), "w", encoding="utf-8") as f:
        f.write(arch + "\n")
    with open(P("classification.txt"), "w", encoding="utf-8") as f:
        f.write(classificacao + "\n")
    ac.gravar_json(P("classification.json"), {"tipo": tipo, "classificacao": classificacao,
                                              "arquitetura": arch, "observacao": obs})
    ac.gravar_json(P("exports_pe.json"), ex)
    ac.gravar_json(P("imports_pe.json"), im)
    ac.gravar_json(P("clr_info.json"), clr)
    with open(P("imports_pe.txt"), "w", encoding="utf-8") as f:
        for x in im:
            f.write("[" + x["dll"] + ("] (delay-load)\n" if x["delay"] else "]\n"))
            for fn in x["functions"]:
                f.write(f"  {fn['address']} ordinal={fn['ordinal']} {fn['name']}\n")
            f.write("\n")
    if ci:
        ac.gravar_json(P("compiler_info.json"), ci)
        with open(P("compiler_info.txt"), "w", encoding="utf-8") as f:
            f.write(texto_compilador(ci))

    # .def com a mesma interface (so para o que tem codigo nativo)
    if tipo != "gerenciada" and ex:
        proj = os.path.join(out, "projeto")
        os.makedirs(proj, exist_ok=True)
        ac.escrever_def(os.path.join(proj, res["nome"] + ".def"),
                        os.path.basename(dll), ex)
    return res


def main():
    if len(sys.argv) < 2:
        print("Uso: classificar_dll.py dll [saida]")
        return 2
    dll = os.path.abspath(sys.argv[1])
    out = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.dirname(dll)
    res = analisar(dll, out)
    if res.get("erro"):
        print(res["erro"])
        return 1
    print("Arquitetura:", res["arquitetura"])
    print("Classificacao:", res["classificacao"], f"[{res['tipo']}]")
    print("Exports:", res["n_exports"])
    if res.get("compilador"):
        print("Compilador sugerido:", res["compilador"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
