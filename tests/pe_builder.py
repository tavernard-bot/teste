# -*- coding: utf-8 -*-
"""Gera PEs minimos (x64) para testar classificar_dll/gerar_projeto sem depender de DLLs reais."""
import struct

IMG = 0x180000000


def construir(caminho, exports=True, clr=None, machine=0x8664, linker=(14, 36)):
    """clr: None | 'il_only' | 'mista'"""
    texto = b"\xC3" * 0x200
    rdata = bytearray(0x400)
    base_rva = 0x2000
    if exports:
        nome_dll = b"mini.dll\0"
        nomes = [b"Alpha\0", b"Beta\0", b"DataVar\0"]
        fwd = b"KERNEL32.Sleep\0"
        off = 40 + 4 * 4 + 4 * 3 + 2 * 3          # dir + funcoes + nomes + ordinais
        pos = {}
        blob = bytearray()
        for k, n in [("dll", nome_dll), ("n0", nomes[0]), ("n1", nomes[1]), ("n2", nomes[2]), ("fwd", fwd)]:
            pos[k] = base_rva + off + len(blob)
            blob += n
        funcs = [0x1000, 0x1010, pos["fwd"], 0x3000]
        names = [pos["n0"], pos["n1"], pos["n2"]]
        ords = [0, 2, 3]
        dirr = struct.pack("<IIHHIIIIIII", 0, 0x5F000000, 0, 0, pos["dll"], 1, 4, 3,
                           base_rva + 40, base_rva + 40 + 16, base_rva + 40 + 16 + 12)
        rdata[0:len(dirr)] = dirr
        p = 40
        for v in funcs:
            struct.pack_into("<I", rdata, p, v); p += 4
        for v in names:
            struct.pack_into("<I", rdata, p, v); p += 4
        for v in ords:
            struct.pack_into("<H", rdata, p, v); p += 2
        rdata[off:off + len(blob)] = blob
    clr_dir = (0, 0)
    if clr:
        flags = 1 if clr == "il_only" else 0
        cor = struct.pack("<IHHIIIIIII", 72, 2, 5, base_rva + 0x200, 0x20, flags, 0, 0, 0, 0)
        rdata[0x100:0x100 + len(cor)] = cor
        clr_dir = (base_rva + 0x100, 72)
    dados = b"\0" * 0x200
    sections = [(b".text", 0x1000, texto, 0x60000020), (b".rdata", 0x2000, bytes(rdata), 0x40000040),
                (b".data", 0x3000, dados, 0xC0000040)]
    raw = 0x400
    shdrs = b""
    corpo = b""
    for nome, rva, dat, ch in sections:
        shdrs += struct.pack("<8sIIIIIIHHI", nome, len(dat), rva, len(dat), raw + len(corpo), 0, 0, 0, 0, ch)
        corpo += dat
    dd = [(0, 0)] * 16
    if exports:
        dd[0] = (base_rva, 40 + 28 + 100)
    if clr:
        dd[14] = clr_dir
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, linker[0], linker[1], 0x200, 0x600, 0, 0x1000, 0x1000,
                      IMG, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x4000, 0x400, 0, 3, 0x8160,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", a, b) for a, b in dd)
    coff = struct.pack("<HHIIIHH", machine, 3, 0x5F000000, 0, 0, len(opt), 0x2022)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    cab = dos + b"PE\0\0" + coff + opt + shdrs
    cab = cab.ljust(0x400, b"\0")
    with open(caminho, "wb") as f:
        f.write(cab + corpo)
