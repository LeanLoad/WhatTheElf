/-
ELF64 `Elf64_Ehdr` — DSL-defined layout, invariants, and parser.

Spec: gabi 02 § ELF Header. Field names match the gabi C struct (`e_type`,
`e_phoff`, …); enum cases are lowercase Lean style (`class64`, `dyn`).

Inline enums are introduced by adding a `{ … }` brace block after the base
scalar width — the macro derives the enum's Lean name from the field name
(e.g. `e_machine : UInt16 { x86_64 = 62 }` makes `Elf64_Ehdr.EMachine`).

Note on `phdrs_after_ehdr`: gabi doesn't *require* `e_phoff ≥ 64` explicitly,
but a phdr table overlapping the ehdr makes the file unloadable by glibc.
Documented spec-policy strengthening, validated by fixtures `15_*` / `17_*`
against `ld.so --verify`.
-/

import WhatTheElf.Basic
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Ehdr where
  ei_magic    : UInt32 { elf = 0x464c457f }
  ei_class    : UInt8  { class32 = 1, class64 = 2 }
  ei_data     : UInt8  { lsb = 1, msb = 2 }
  ei_version  : UInt8  { current = 1 }
  ei_osabi    : UInt8  { sysv = 0, hpux = 1, netbsd = 2, gnu = 3,
                      solaris = 6, aix = 7, irix = 8, freebsd = 9,
                      tru64 = 10, modesto = 11, openbsd = 12,
                      openvms = 13, nsk = 14, aros = 15, fenixos = 16,
                      cloudabi = 17, openvos = 18, other = _ }
  ei_abiver   : UInt8
  ei_pad      : Bytes 7
  e_type      : UInt16 { none = 0, rel = 1, exec = 2, dyn = 3, core = 4,
                      osSpecific = 0xfe00..0xfeff,
                      procSpecific = 0xff00..0xffff }
  e_machine   : UInt16 { em_none = 0, em_m32 = 1, em_sparc = 2, em_386 = 3, em_68k = 4,
                      em_88k = 5, em_iamcu = 6, em_860 = 7, em_mips = 8, em_s370 = 9,
                      em_mips_rs3_le = 10, em_parisc = 15, em_vpp500 = 17,
                      em_sparc32plus = 18, em_960 = 19, em_ppc = 20, em_ppc64 = 21,
                      em_s390 = 22, em_spu = 23, em_v800 = 36, em_fr20 = 37, em_rh32 = 38,
                      em_rce = 39, em_arm = 40, em_alpha = 41, em_sh = 42, em_sparcv9 = 43,
                      em_tricore = 44, em_arc = 45, em_h8_300 = 46, em_h8_300h = 47,
                      em_h8s = 48, em_h8_500 = 49, em_ia_64 = 50, em_mips_x = 51,
                      em_coldfire = 52, em_68hc12 = 53, em_mma = 54, em_pcp = 55,
                      em_ncpu = 56, em_ndr1 = 57, em_starcore = 58, em_me16 = 59,
                      em_st100 = 60, em_tinyj = 61, em_x86_64 = 62, em_pdsp = 63,
                      em_pdp10 = 64, em_pdp11 = 65, em_fx66 = 66, em_st9plus = 67,
                      em_st7 = 68, em_68hc16 = 69, em_68hc11 = 70, em_68hc08 = 71,
                      em_68hc05 = 72, em_svx = 73, em_st19 = 74, em_vax = 75, em_cris = 76,
                      em_javelin = 77, em_firepath = 78, em_zsp = 79, em_mmix = 80,
                      em_huany = 81, em_prism = 82, em_avr = 83, em_fr30 = 84, em_d10v = 85,
                      em_d30v = 86, em_v850 = 87, em_m32r = 88, em_mn10300 = 89,
                      em_mn10200 = 90, em_pj = 91, em_openrisc = 92, em_arc_compact = 93,
                      em_xtensa = 94, em_videocore = 95, em_tmm_gpp = 96, em_ns32k = 97,
                      em_tpc = 98, em_snp1k = 99, em_st200 = 100, em_ip2k = 101,
                      em_max = 102, em_cr = 103, em_f2mc16 = 104, em_msp430 = 105,
                      em_blackfin = 106, em_se_c33 = 107, em_sep = 108, em_arca = 109,
                      em_unicore = 110, em_excess = 111, em_dxp = 112, em_altera_nios2 = 113,
                      em_crx = 114, em_xgate = 115, em_c166 = 116, em_m16c = 117,
                      em_dspic30f = 118, em_ce = 119, em_m32c = 120, em_tsk3000 = 131,
                      em_rs08 = 132, em_sharc = 133, em_ecog2 = 134, em_score7 = 135,
                      em_dsp24 = 136, em_videocore3 = 137, em_latticemico32 = 138,
                      em_se_c17 = 139, em_ti_c6000 = 140, em_ti_c2000 = 141,
                      em_ti_c5500 = 142, em_ti_arp32 = 143, em_ti_pru = 144,
                      em_mmdsp_plus = 160, em_cypress_m8c = 161, em_r32c = 162,
                      em_trimedia = 163, em_qdsp6 = 164, em_8051 = 165, em_stxp7x = 166,
                      em_nds32 = 167, em_ecog1 = 168, em_maxq30 = 169, em_ximo16 = 170,
                      em_manik = 171, em_craynv2 = 172, em_rx = 173, em_metag = 174,
                      em_mcst_elbrus = 175, em_ecog16 = 176, em_cr16 = 177, em_etpu = 178,
                      em_sle9x = 179, em_l10m = 180, em_k10m = 181, em_aarch64 = 183,
                      em_avr32 = 185, em_stm8 = 186, em_tile64 = 187, em_tilepro = 188,
                      em_microblaze = 189, em_cuda = 190, em_tilegx = 191,
                      em_cloudshield = 192, em_corea_1st = 193, em_corea_2nd = 194,
                      em_arc_compact2 = 195, em_open8 = 196, em_rl78 = 197,
                      em_videocore5 = 198, em_78kor = 199, em_56800ex = 200, em_ba1 = 201,
                      em_ba2 = 202, em_xcore = 203, em_mchp_pic = 204, em_intel205 = 205,
                      em_intel206 = 206, em_intel207 = 207, em_intel208 = 208,
                      em_intel209 = 209, em_km32 = 210, em_kmx32 = 211, em_kmx16 = 212,
                      em_kmx8 = 213, em_kvarc = 214, em_cdp = 215, em_coge = 216,
                      em_cool = 217, em_norc = 218, em_csr_kalimba = 219, em_z80 = 220,
                      em_visium = 221, em_ft32 = 222, em_moxie = 223, em_amdgpu = 224,
                      em_riscv = 243, em_lanai = 244, em_ceva = 245, em_ceva_x2 = 246,
                      em_bpf = 247, em_graphcore_ipu = 248, em_img1 = 249, em_nfp = 250,
                      em_ve = 251, em_csky = 252, em_arc_compact3_64 = 253, em_mcs6502 = 254,
                      em_arc_compact3 = 255, em_kvx = 256, em_65816 = 257,
                      em_loongarch = 258, em_kf32 = 259, em_u16_u8core = 260,
                      em_tachyum = 261, em_56800ef = 262, em_sbf = 263, em_aiengine = 264,
                      em_sima_mla = 265, em_bang = 266, em_loonggpu = 267, em_sw64 = 268,
                      other = _ }
  e_version   : UInt32 { current = 1 }
  e_entry     : Addr
  e_phoff     : Off
  e_shoff     : Off
  e_flags     : UInt32
  e_ehsize    : UInt16
  e_phentsize : UInt16
  e_phnum     : UInt16
  e_shentsize : UInt16
  e_shnum     : UInt16
  e_shstrndx  : UInt16
invariant
  class_ok      : ei_class           = .class64
  data_ok       : ei_data            = .lsb
  not_exec      : e_type             ≠ .exec
  machine_ok    : e_machine = .em_x86_64 ∨ e_machine = .em_aarch64
  ehsize_ok        : e_ehsize.toNat     = 64
  phentsize_ok     : e_phentsize.toNat  = 56
  shentsize_ok     : e_shoff.toNat = 0 ∨ e_shentsize.toNat = 64
  phdrs_after_ehdr : e_phnum.toNat = 0 ∨ e_phoff.toNat ≥ 64

end WhatTheElf
