#!/usr/bin/python3

import capstone
# pip3 install keystone-engine
import keystone
haveunicorn = False
try:
    import unicorn
    haveunicorn = True
except ModuleNotFoundError:
    pass
try:
    import readline
except ModuleNotFoundError:
    pass

AP_MODE_ASM = "asm"
AP_MODE_DIS = "dis"
AP_MODE_EMU = "emu"
AP_MODES = [AP_MODE_ASM, AP_MODE_DIS, AP_MODE_EMU]

AP_ARCH_X86 = "x86"
AP_ARCH_ARM = "arm"
AP_ARCH_ARM64 = "arm64"
AP_ARCHS = [AP_ARCH_X86, AP_ARCH_ARM, AP_ARCH_ARM64]

AP_BITS_16 = "16"
AP_BITS_32 = "32"
AP_BITS_64 = "64"
AP_BITS_ARM = "arm"
AP_BITS_ARMBE = "arm_be"
AP_BITS_THUMB = "thumb"
AP_BITS_THUMBBE = "thumb_be"
AP_BITS_DEF = "def"
AP_BITS_FOR_ARM = [AP_BITS_ARM, AP_BITS_ARMBE, AP_BITS_THUMB, AP_BITS_THUMBBE, AP_BITS_DEF]
AP_BITS_FOR_X86 = [AP_BITS_16, AP_BITS_32, AP_BITS_64, AP_BITS_DEF]
AP_BITS = AP_BITS_FOR_X86 + AP_BITS_FOR_ARM

AP_SYNT_ATT = "att"
AP_SYNT_GAS = "gas"
AP_SYNT_INTEL = "intel"
AP_SYNT_MASM = "masm"
AP_SYNT_NASM = "nasm"
AP_SYNT_DEF = "def"
AP_SYNTS = [AP_SYNT_ATT, AP_SYNT_GAS, AP_SYNT_INTEL, AP_SYNT_MASM, AP_SYNT_NASM, AP_SYNT_DEF]

arch2cs = {
    AP_ARCH_X86 : capstone.CS_ARCH_X86,
    AP_ARCH_ARM : capstone.CS_ARCH_ARM,
    AP_ARCH_ARM64 : capstone.CS_ARCH_ARM64,
}
bits2cs = {
    AP_BITS_16 : capstone.CS_MODE_16,
    AP_BITS_32 : capstone.CS_MODE_32,
    AP_BITS_64 : capstone.CS_MODE_64,
    AP_BITS_ARM : capstone.CS_MODE_ARM,
    AP_BITS_ARMBE : capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN,
    AP_BITS_THUMB : capstone.CS_MODE_THUMB,
    AP_BITS_THUMBBE : capstone.CS_MODE_THUMB | capstone.CS_MODE_BIG_ENDIAN,
    AP_BITS_DEF : 0,
}
synt2cs = {
    AP_SYNT_ATT : capstone.CS_OPT_SYNTAX_ATT,
    AP_SYNT_GAS : capstone.CS_OPT_SYNTAX_ATT,
    AP_SYNT_INTEL : capstone.CS_OPT_SYNTAX_INTEL,
    AP_SYNT_MASM : capstone.CS_OPT_SYNTAX_MASM,
    AP_SYNT_NASM : capstone.CS_OPT_SYNTAX_INTEL,
    AP_SYNT_DEF : 0,
}

arch2uc = None
bits2uc = None
if haveunicorn:
    arch2uc = {
        AP_ARCH_X86 : unicorn.UC_ARCH_X86,
        AP_ARCH_ARM : unicorn.UC_ARCH_ARM,
        AP_ARCH_ARM64 : unicorn.UC_ARCH_ARM64,
    }
    bits2uc = {
        AP_BITS_16 : unicorn.UC_MODE_16,
        AP_BITS_32 : unicorn.UC_MODE_32,
        AP_BITS_64 : unicorn.UC_MODE_64,
        AP_BITS_ARM : unicorn.UC_MODE_ARM,
        AP_BITS_ARMBE : unicorn.UC_MODE_ARM | unicorn.UC_MODE_BIG_ENDIAN,
        AP_BITS_THUMB : unicorn.UC_MODE_THUMB,
        AP_BITS_THUMBBE : unicorn.UC_MODE_THUMB | unicorn.UC_MODE_BIG_ENDIAN,
        AP_BITS_DEF : 0,
    }

arch2ks = {
    AP_ARCH_X86 : keystone.KS_ARCH_X86,
    AP_ARCH_ARM : keystone.KS_ARCH_ARM,
    AP_ARCH_ARM64 : keystone.KS_ARCH_ARM64,
}
bits2ks = {
    AP_BITS_16 : keystone.KS_MODE_16,
    AP_BITS_32 : keystone.KS_MODE_32,
    AP_BITS_64 : keystone.KS_MODE_64,
    AP_BITS_ARM : keystone.KS_MODE_ARM,
    AP_BITS_ARMBE : keystone.KS_MODE_ARM | keystone.KS_MODE_BIG_ENDIAN,
    AP_BITS_THUMB : keystone.KS_MODE_THUMB,
    AP_BITS_THUMBBE : keystone.KS_MODE_THUMB | keystone.KS_MODE_BIG_ENDIAN,
    AP_BITS_DEF : 0,
}
synt2ks = {
    AP_SYNT_ATT : keystone.KS_OPT_SYNTAX_ATT,
    AP_SYNT_GAS : keystone.KS_OPT_SYNTAX_GAS,
    AP_SYNT_INTEL : keystone.KS_OPT_SYNTAX_INTEL,
    AP_SYNT_MASM : keystone.KS_OPT_SYNTAX_MASM,
    AP_SYNT_NASM : keystone.KS_OPT_SYNTAX_NASM,
    AP_SYNT_DEF : 0,
}

CMDS = \
"""
In ASM or EMU mode:
    <assembly ending in empty line>
In DIS mode:
    <hex encoded bytes to be disassembled ending in empty line>
Mode Commands:
    MODE (ASM|DIS|EMU)
    ARCH (X86|ARM|ARM64)
    BITS (16|32|64|ARM|THUMB|ARM_BE|THUMB_BE)   # depends on the current arch
    SYNT (NASM|ATT)                             # applies to x86 arch
    INFO                                        # get current mode info
    HELP                                        # print this text
    QUIT
"""

WELCOME = \
"""
 /\  _ _ |  . _  _ 
/--\_)||||__|| )(- 

""" + CMDS

PROMPTE = " > "

def hex2b(ins):
    ins = ins.translate({ord(x): None for x in " \t\n-:"})
    return bytes.fromhex(ins)

def disassemble_bytes(inb, arch, bits, synt=AP_SYNT_DEF, withbytes=False):
    cs = capstone.Cs(arch2cs[arch], bits2cs[bits])
    if synt != AP_SYNT_DEF:
        cs.syntax = synt2cs[synt]
    out = ""
    for i in cs.disasm(inb, 0):
        if withbytes:
            out += i.bytes.hex() + ' '
        out += i.mnemonic + ' ' + i.op_str + '\n'

    return out
    

def disassemble_hex(ins, arch, bits, synt=AP_SYNT_DEF):
    inb = hex2b(ins)
    return disassemble_bytes(inb, arch, bits, synt)

def emulate(ins, arch, bits, synt=AP_SYNT_DEF):
    if not haveunicorn:
        raise Exception("Must have unicorn engine installed to use emulate feature")

    code = assemble(ins, arch, bits, synt)

    addr = 0x0000
    uc = unicorn.Uc(arch2uc[arch], bits2uc[bits])
    PGSZ = 0x1000
    roundup = (len(code) + (PGSZ-1)) & (~(PGSZ-1))
    uc.mem_map(addr, roundup)
    uc.mem_write(addr, code)
    
    try:
        uc.emu_start(addr, addr+len(code))
    except unicorn.UcError as e:
        print("Got Emulation error:", e)

    # dump state
    #TODO pair this down to something smaller per arch
    # we don't need all of this each time
    rgmod = None
    prefix = ""
    if arch == AP_ARCH_ARM:
        prefix = "UC_ARM_REG_"
        rgmod = unicorn.arm_const
    elif arch == AP_ARCH_ARM64:
        prefix = "UC_ARM64_REG_"
        rgmod = unicorn.arm64_const
    elif arch == AP_ARCH_X86:
        prefix = "UC_X86_REG_"
        rgmod = unicorn.x86_const

    for r in dir(rgmod):
        if r.startswith(prefix):
            rg = getattr(rgmod, r)
            try:
                rval = uc.reg_read(rg)
            except unicorn.UcError:
                continue
            if isinstance(rval, int):
                print(r[len(prefix):], '=', hex(rval))

def assemble(ins, arch, bits, synt=AP_SYNT_DEF):
    ks = keystone.Ks(arch2ks[arch], bits2ks[bits])
    if synt != AP_SYNT_DEF:
        ks.syntax = synt2ks[synt]
    b, _ = ks.asm(ins)
    return bytes(b)

def get_prompt(mode, arch, bits, synt=AP_SYNT_DEF):
    archbits = arch
    if arch == AP_ARCH_X86:
        archbits += '_'+ bits
    elif bits in AP_BITS_FOR_ARM:
        if bits in [AP_BITS_THUMB, AP_BITS_THUMBBE]:
            archbits += "(thumb)"
        if bits in [AP_BITS_ARMBE, AP_BITS_THUMBBE]:
            archbits += "(BE)"
    return mode.upper() +' '+ archbits + PROMPTE

def get_info(mode, arch, bits, synt=AP_SYNT_DEF):
    out = ""
    out += "MODE: " + mode.upper() + "\n"
    out += "ARCH: " + arch.upper() + "\n"
    if bits != AP_BITS_DEF:
        out += "BITS: " + bits.upper() + "\n"
    if arch == "x86" and synt != AP_SYNT_DEF:
        out += "SYNT: " + synt.upper() + "\n"
    return out

def main():
    mode = AP_MODE_ASM
    arch = AP_ARCH_X86
    bits = AP_BITS_64
    synt = AP_SYNT_DEF

    #TODO parse cmd args

    print(WELCOME)

    while True:
        prompt = get_prompt(mode, arch, bits, synt)
        try:
            cmd = input(prompt).strip()
        except EOFError:
            break
        
        if len(cmd) == 0:
            continue

        # handle special commands
        scmd = cmd.lower().split()
        if scmd[0] == 'mode':
            if len(scmd) != 2:
                print("MODE Expected 1 argument")
                continue
            if scmd[1] not in AP_MODES:
                print("Unsupported mode")
                continue
            mode = scmd[1]
            continue
        elif scmd[0] == 'arch':
            if len(scmd) != 2:
                print("ARCH Expected 1 argument")
                continue
            if scmd[1] not in AP_ARCHS:
                print("Unsupported mode")
                continue
            arch = scmd[1]

            # set bits and synt to default
            if arch == AP_ARCH_ARM64:
                bits = AP_BITS_DEF
                synt = AP_SYNT_DEF
            if arch == AP_ARCH_ARM:
                bits = AP_BITS_ARM
                synt = AP_SYNT_DEF
            elif arch == AP_ARCH_X86:
                bits = AP_BITS_64
                synt = AP_SYNT_NASM

            continue
        elif scmd[0] == 'bits':
            if len(scmd) != 2:
                print("BITS Expected 1 argument")
                continue
            if scmd[1] not in AP_BITS:
                print("Unsupported mode")
                continue
            if arch in [AP_ARCH_ARM, AP_ARCH_ARM64] and scmd[1] not in AP_BITS_FOR_ARM:
                print("Unsupported bits for current arch")
                continue
            elif arch == AP_ARCH_X86 and scmd[1] not in AP_BITS_FOR_X86:
                print("Unsupported bits for current arch")
                continue
            bits = scmd[1]
            continue
        elif scmd[0] == 'synt':
            if len(scmd) != 2:
                print("SYNT Expected 1 argument")
                continue
            if scmd[1] not in AP_SYNTS:
                print("Unsupported mode")
                continue
            if arch in [AP_ARCH_ARM, AP_ARCH_ARM64]:
                print("SYNT unsupported for current arch")
                continue
            synt = scmd[1]
            continue
        elif scmd[0] == 'info':
            print(get_info(mode, arch, bits, synt))
            continue
        elif scmd[0] == 'help':
            print(CMDS)
            continue
        elif scmd[0] == 'quit':
            break

        plen = len(prompt) - len(PROMPTE)
        prompt = (' ' * plen) + PROMPTE

        # get rest of input
        while True:
            n = input(prompt).strip()
            if n == "":
                break
            cmd += '\n' + n

        # hand off
        try:
            if mode == AP_MODE_ASM:
                asm = assemble(cmd, arch, bits, synt)
                sp = 0x8
                nl = 0x10
                for i in range(0, len(asm), sp):
                    print(asm[i:i+sp].hex(), end=' ')
                    if ((i+sp) % nl) == 0 and (i+sp) < len(asm):
                        print('')
                print('')
            elif mode == AP_MODE_DIS:
                dis = disassemble_hex(cmd, arch, bits, synt)
                print(dis)
            elif mode == AP_MODE_EMU:
                emulate(cmd, arch, bits, synt)
            
            print('') 
        except Exception as e:
            print(e)

    print("")
    return
        
if __name__ == '__main__':
    main()
