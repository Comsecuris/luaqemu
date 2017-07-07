--[[
Capstone has been designed & implemented by Nguyen Anh Quynh <aquynh@gmail.com>

See http://www.capstone-engine.org for further information.

Copyright (c) 2013, COSEINC.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of the developer(s) nor the names of its
  contributors may be used to endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
--]]

ffi.cdef[[
// Handle using with all API
typedef size_t csh;

// Architecture type
typedef enum cs_arch {
    CS_ARCH_ARM = 0,    // ARM architecture (including Thumb, Thumb-2)
    CS_ARCH_ARM64,      // ARM-64, also called AArch64
    CS_ARCH_MIPS,       // Mips architecture
    CS_ARCH_X86,        // X86 architecture (including x86 & x86-64)
    CS_ARCH_PPC,        // PowerPC architecture
    CS_ARCH_SPARC,      // Sparc architecture
    CS_ARCH_SYSZ,       // SystemZ architecture
    CS_ARCH_XCORE,      // XCore architecture
    CS_ARCH_MAX,
    CS_ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
} cs_arch;

// Mode type
typedef enum cs_mode {
    CS_MODE_LITTLE_ENDIAN = 0,  // little-endian mode (default mode)
    CS_MODE_ARM = 0,    // 32-bit ARM
    CS_MODE_16 = 1 << 1,    // 16-bit mode (X86)
    CS_MODE_32 = 1 << 2,    // 32-bit mode (X86)
    CS_MODE_64 = 1 << 3,    // 64-bit mode (X86, PPC)
    CS_MODE_THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    CS_MODE_MCLASS = 1 << 5,    // ARM's Cortex-M series
    CS_MODE_V8 = 1 << 6,    // ARMv8 A32 encodings for ARM
    CS_MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
    CS_MODE_MIPS3 = 1 << 5, // Mips III ISA
    CS_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
    CS_MODE_MIPSGP64 = 1 << 7, // General Purpose Registers are 64-bit wide (MIPS)
    CS_MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
    CS_MODE_BIG_ENDIAN = 1 << 31,   // big-endian mode
    CS_MODE_MIPS32 = CS_MODE_32,    // Mips32 ISA (Mips)
    CS_MODE_MIPS64 = CS_MODE_64,    // Mips64 ISA (Mips)
} cs_mode;

typedef void* (*cs_malloc_t)(size_t size);
typedef void* (*cs_calloc_t)(size_t nmemb, size_t size);
typedef void* (*cs_realloc_t)(void *ptr, size_t size);
typedef void (*cs_free_t)(void *ptr);
typedef int (*cs_vsnprintf_t)(char *str, size_t size, const char *format, va_list ap);

// User-defined dynamic memory related functions: malloc/calloc/realloc/free/vsnprintf()
// By default, Capstone uses system's malloc(), calloc(), realloc(), free() & vsnprintf().
typedef struct cs_opt_mem {
    cs_malloc_t malloc;
    cs_calloc_t calloc;
    cs_realloc_t realloc;
    cs_free_t free;
    cs_vsnprintf_t vsnprintf;
} cs_opt_mem;

// Runtime option for the disassembled engine
typedef enum cs_opt_type {
    CS_OPT_INVALID = 0, // No option specified
    CS_OPT_SYNTAX,  // Assembly output syntax
    CS_OPT_DETAIL,  // Break down instruction structure into details
    CS_OPT_MODE,    // Change engine's mode at run-time
    CS_OPT_MEM, // User-defined dynamic memory related functions
    CS_OPT_SKIPDATA, // Skip data when disassembling. Then engine is in SKIPDATA mode.
    CS_OPT_SKIPDATA_SETUP, // Setup user-defined function for SKIPDATA option
} cs_opt_type;

// Runtime option value (associated with option type above)
typedef enum cs_opt_value {
    CS_OPT_OFF = 0,  // Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA.
    CS_OPT_ON = 3, // Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
    CS_OPT_SYNTAX_DEFAULT = 0, // Default asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_INTEL, // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_ATT,   // X86 ATT asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_NOREGNAME, // Prints register name with only number (CS_OPT_SYNTAX)
} cs_opt_value;

//> Common instruction groups - to be consistent across all architectures.
typedef enum cs_group_type {
    CS_GRP_INVALID = 0,  // uninitialized/invalid group.
    CS_GRP_JUMP,    // all jump instructions (conditional+direct+indirect jumps)
    CS_GRP_CALL,    // all call instructions
    CS_GRP_RET,     // all return instructions
    CS_GRP_INT,     // all interrupt instructions (int+syscall)
    CS_GRP_IRET,    // all interrupt return instructions
} cs_group_type;

// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
typedef struct cs_detail {
    uint8_t regs_read[12]; // list of implicit registers read by this insn
    uint8_t regs_read_count; // number of implicit registers read by this insn

    uint8_t regs_write[20]; // list of implicit registers modified by this insn
    uint8_t regs_write_count; // number of implicit registers modified by this insn

    uint8_t groups[8]; // list of group this instruction belong to
    uint8_t groups_count; // number of groups this insn belongs to

    // Architecture-specific instruction info
    union {
       cs_x86 x86; // X86 architecture, including 16-bit, 32-bit & 64-bit mode
       //cs_arm64 arm64; // ARM64 architecture (aka AArch64)
       cs_arm arm;     // ARM architecture (including Thumb/Thumb2)
       //cs_mips mips;   // MIPS architecture
       //cs_ppc ppc; // PowerPC architecture
       //cs_sparc sparc; // Sparc architecture
       //cs_sysz sysz;   // SystemZ architecture
       //cs_xcore xcore; // XCore architecture
    };
} cs_detail;

// Detail information of disassembled instruction
typedef struct cs_insn {
    // Instruction ID (basically a numeric ID for the instruction mnemonic)
    // Find the instruction id in the '[ARCH]_insn' enum in the header file 
    // of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    // 'x86_insn' in x86.h for X86, etc...
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    // NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    unsigned int id;

    // Address (EIP) of this instruction
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    uint64_t address;

    // Size of this instruction
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    uint16_t size;
    // Machine bytes of this instruction, with number of bytes indicated by @size above
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    uint8_t bytes[16];

    // Ascii text of instruction mnemonic
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    char mnemonic[32];

    // Ascii text of instruction operands
    // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    char op_str[160];

    // Pointer to cs_detail.
    // NOTE: detail pointer is only valid when both requirements below are met:
    // (1) CS_OP_DETAIL = CS_OPT_ON
    // (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    //
    // NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    //     is not NULL, its content is still irrelevant.
    cs_detail *detail;
} cs_insn;

// All type of errors encountered by Capstone API.
// These are values returned by cs_errno()
typedef enum cs_err {
    CS_ERR_OK = 0,   // No error: everything was fine
    CS_ERR_MEM,      // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_ARCH,     // Unsupported architecture: cs_open()
    CS_ERR_HANDLE,   // Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_CSH,      // Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_MODE,     // Invalid/unsupported mode: cs_open()
    CS_ERR_OPTION,   // Invalid/unsupported option: cs_option()
    CS_ERR_DETAIL,   // Information is unavailable because detail option is OFF
    CS_ERR_MEMSETUP, // Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_VERSION,  // Unsupported version (bindings)
    CS_ERR_DIET,     // Access irrelevant data in "diet" engine
    CS_ERR_SKIPDATA, // Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_X86_ATT,  // X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL, // X86 Intel syntax is unsupported (opt-out at compile time)
} cs_err;

unsigned int cs_version(int *major, int *minor);
bool cs_support(int query);
cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);
cs_err cs_close(csh *handle);
cs_err cs_option(csh handle, cs_opt_type type, size_t value);
cs_err cs_errno(csh handle);
const char * cs_strerror(cs_err code);
size_t cs_disasm(csh handle,
        const uint8_t *code, size_t code_size,
        uint64_t address,
        size_t count,
        cs_insn **insn);
void cs_free(cs_insn *insn, size_t count);
cs_insn * cs_malloc(csh handle);
bool cs_disasm_iter(csh handle,
    const uint8_t **code, size_t *size,
    uint64_t *address, cs_insn *insn);
const char * cs_reg_name(csh handle, unsigned int reg_id);
const char * cs_insn_name(csh handle, unsigned int insn_id);
const char * cs_group_name(csh handle, unsigned int group_id);
bool cs_insn_group(csh handle, const cs_insn *insn, unsigned int group_id);
bool cs_reg_read(csh handle, const cs_insn *insn, unsigned int reg_id);
bool cs_reg_write(csh handle, const cs_insn *insn, unsigned int reg_id);
int cs_op_count(csh handle, const cs_insn *insn, unsigned int op_type);
int cs_op_index(csh handle, const cs_insn *insn, unsigned int op_type,
        unsigned int position);
]]
