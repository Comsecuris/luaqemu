/* Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef _LUAARM_H_
#define _LUAARM_H_

#define THROW_ERROR 1
#define NOTHROW_ERROR 0
#define TPR_NAME_SIZE	64

typedef struct {
    void *opaque;
    hwaddr addr;
    uint64_t size;
} TprReadCbArgs;

typedef struct {
    void *opaque;
    hwaddr addr;
    uint64_t data;
    uint64_t size;
} TprWriteCbArgs;

typedef struct {
    uint64_t addr;
    uint64_t len;
    uint64_t flags;
} watchpoint_args_t;

typedef void     (*watchpoint_cb)(watchpoint_args_t *args);
typedef void     (*TprReadCb)(TprReadCbArgs *args);
typedef void     (*TprWriteCb)(TprWriteCbArgs *args);

typedef struct {
    MemoryRegionOps ops;
    MemoryRegion region;
    TprReadCb readCb;
    TprWriteCb writeCb;    
    char name[TPR_NAME_SIZE];    
} TrappedPhysRegion;

typedef struct {
    uint64_t addr;
    uint64_t len;
    int flags;
    watchpoint_cb fptr;
} watchpoint_t;

typedef struct {
    ARMCPU *cpu;
    CPUState *cs;
    MachineState *machine;
    uint64_t bp_pc;
    uint64_t *bp_pc_ptr;
    watchpoint_t *old_wp_ptr;

    /* callbacks */
    int stuck_state_cb; /* registry id of lua function to be called */
    int exec_insn_cb;  /* called before the emulation of an instruction */
    int exec_block_cb; /* called before the execution of a basic block */
    int post_exec_block_cb; /* called after the execution of a basic block */

} luastate_t;

/* prototypes */
uint64_t trapped_physregion_read(void *opaque, hwaddr addr, unsigned size);
void trapped_physregion_write(void *opaque, hwaddr addr, uint64_t data, unsigned size);

/* externally called function prototypes */
void lua_cpu_exec_insn_callback(uint64_t pc, uint64_t insn);
void lua_cpu_exec_block_callback(uint64_t pc);
void lua_cpu_post_exec_block_callback(uint64_t pc);


#endif /* _LUAARM_H_ */
