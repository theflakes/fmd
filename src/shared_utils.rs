use crate::data_defs::Architecture;
use goblin::elf;
use goblin::mach;
use goblin::pe;

pub fn get_arch_elf(e_machine: u16) -> Architecture {
    match e_machine {
        elf::header::EM_X86_64 => Architecture::X86_64,
        elf::header::EM_386 => Architecture::X86,
        elf::header::EM_ARM => Architecture::Arm,
        elf::header::EM_AARCH64 => Architecture::AArch64,
        elf::header::EM_MIPS => Architecture::Mips,
        elf::header::EM_PPC => Architecture::PowerPC,
        elf::header::EM_RISCV => Architecture::RiscV,
        elf::header::EM_IA_64 => Architecture::Itanium,
        _ => Architecture::Unknown,
    }
}

pub fn get_arch_macho(cputype: u32) -> Architecture {
    match cputype {
        mach::constants::cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
        mach::constants::cputype::CPU_TYPE_X86 => Architecture::X86,
        mach::constants::cputype::CPU_TYPE_ARM => Architecture::Arm,
        mach::constants::cputype::CPU_TYPE_ARM64 => Architecture::AArch64,
        mach::constants::cputype::CPU_TYPE_POWERPC => Architecture::PowerPC,
        _ => Architecture::Unknown,
    }
}

pub fn get_arch_pe(machine: u16) -> Architecture {
    match machine {
        pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
        pe::header::COFF_MACHINE_X86 => Architecture::X86,
        pe::header::COFF_MACHINE_ARM => Architecture::Arm,
        pe::header::COFF_MACHINE_ARMNT => Architecture::AArch64,
        pe::header::COFF_MACHINE_POWERPC => Architecture::PowerPC,
        pe::header::COFF_MACHINE_IA64 => Architecture::Itanium,
        _ => Architecture::Unknown,
    }
}
