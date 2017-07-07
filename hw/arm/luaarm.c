/*
 * lua board definition
 *
 * Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt) luaqemu@comsecuris.com
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
TODO:
- proper error handling for malformed lua tables
- convert all lua_get_* handlers so that the return value is used to indicate an
  error while passing the return as a parameter. this way we can get rid of this error
  parameter handling that makes lua_get_field unflexible
- think about how to handle multiple breakpoints on the same address
- handle multicore environments
- modularize vm_state_change (right now its mostly the breakpoint handler ;)
- add flag for endianness to cpu environment (ARM can be both big endian and little endian)
  -> document using a flush/sync if this is wanted and memory is modified
- wrap lua_* calls so that callbacks can be free'd once they are removed (bp/wp)
*/

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "net/net.h"
#include "qemu/error-report.h"
#include "hw/devices.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/arm/arm.h"
#include "hw/arm/luaarm.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "sysemu/qtest.h"
#include "cpu.h"
#include "elf.h"
#include "exec/exec-all.h"
#include "qemu/config-file.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static luastate_t luastate;

GHashTable* breakpoints = NULL;
GList *trapped_physregions = NULL;
GList *watchpoints = NULL;

#define DEBUG 0
#define debug_print(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, "%s:%d " fmt, __func__, __LINE__, __VA_ARGS__); } while (0);

static void util_watchpoint_insert(uint64_t addr, uint64_t size, int flags, watchpoint_cb cb)
{
    watchpoint_t *wp;
    debug_print("adding watchpoint covering '%" PRIx64 "-%" PRIx64 " (flags: %x)\n", addr, (addr + size), flags);

    flags |= BP_STOP_BEFORE_ACCESS;

    wp = g_malloc0(sizeof(*wp));
    wp->addr = addr;
    wp->len = size;
    wp->flags = flags;
    wp->fptr = cb;

    cpu_watchpoint_insert(luastate.cs, addr, size, flags, NULL);

    if (NULL == (watchpoints = g_list_append(watchpoints, wp))) {
        error_report("%s error adding watchpoint\n", __func__);
        g_free(wp);
    }
}

static void util_watchpoint_remove(uint64_t addr, uint64_t size, int flags)
{
    GList *iterator;
    watchpoint_t *wp;

    for(iterator = watchpoints; iterator; iterator = iterator->next) {
        wp = iterator->data;
        if (wp->addr == addr && wp->len == size && wp->flags == flags) {
            watchpoints = g_list_delete_link(watchpoints, iterator);
            cpu_watchpoint_remove(luastate.cs, wp->addr, wp->len, wp->flags);
            g_free(wp);
            return;
        }
    }
    error_report("%s could not find matching watchpoint\n", __func__);
}

static void util_breakpoint_insert(uint64_t addr, int bp_func)
{
    printf("adding breakpoint for '%" PRIx64 "' -> '%d'\n", addr, bp_func);

    /* we can't use BP_CPU here as all CPU breakpoints are removed on a reset.
       we can't use BP_GDB either as in that case we will run into crashes in
       code that assumes there is also a gdbserver state
     */
    if(luastate.cs) {
        cpu_breakpoint_insert(luastate.cs, addr, BP_LUA, NULL);
    }
    g_hash_table_insert(breakpoints, GUINT_TO_POINTER(addr), GINT_TO_POINTER(bp_func));
}

static void util_breakpoint_remove(uint64_t addr)
{
    int bp_fun = GPOINTER_TO_INT(g_hash_table_lookup(breakpoints, GUINT_TO_POINTER(addr)));
    if (!bp_fun) {
        error_report("%s no breakpoint found for %" PRIx64 "\n", __func__, addr);
        return;
    }

    printf("removing breakpoint for '%" PRIx64 "'\n", addr);
    luaL_unref(lua_state, LUA_REGISTRYINDEX, bp_fun);
    cpu_breakpoint_remove(luastate.cs, addr, BP_LUA);
    g_hash_table_remove(breakpoints, GUINT_TO_POINTER(addr));
}

#define LUAQEMU_DEBUG


/* function stolen from memory.c */
static hwaddr memory_region_to_absolute_addr(MemoryRegion *mr, hwaddr offset)
{
    MemoryRegion *root;
    hwaddr abs_addr = offset;

    abs_addr += mr->addr;
    for (root = mr; root->container; ) {
        root = root->container;
        abs_addr += root->addr;
    }

    return abs_addr;
}


uint64_t trapped_physregion_read(void *opaque, hwaddr addr, unsigned size)
{
    TrappedPhysRegion *tpr = opaque;
    TprReadCbArgs cbArgs;
    hwaddr addr2;

    addr2 = memory_region_to_absolute_addr(&tpr->region, addr);    

    debug_print("trapped_physregion_read hit @ %" PRIx64 " size = %d\n", addr2, size);

    cbArgs.opaque = opaque;
    cbArgs.addr = addr2;
    cbArgs.size = size;
    tpr->readCb(&cbArgs);

    return 0;
}

void trapped_physregion_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    TrappedPhysRegion *tpr = opaque;
    TprWriteCbArgs cbArgs;
    hwaddr addr2;

    addr2 = memory_region_to_absolute_addr(&tpr->region, addr);

    debug_print("trapped_physregion_write hit @ %" PRIx64 " size = %d\n", addr2, size);

    cbArgs.opaque = opaque;
    cbArgs.addr = addr2;
    cbArgs.data = data;
    cbArgs.size = size;
    tpr->writeCb(&cbArgs);
}

#undef LUAQEMU_DEBUG

static void util_trapped_physregion_add(uint64_t addr, uint64_t size, TprReadCb readCb, TprWriteCb writeCb)
{
    TrappedPhysRegion *tpr;
    MemoryRegion *sysmem = get_system_memory();    

    printf("adding trapped physregion '%" PRIx64 "-%" PRIx64 "'\n", addr, (addr + size));    

    tpr = g_malloc0(sizeof(TrappedPhysRegion));

    tpr->readCb = readCb;
    tpr->writeCb = writeCb;

    tpr->ops.read = trapped_physregion_read;
    tpr->ops.write = trapped_physregion_write;
    tpr->ops.endianness = DEVICE_NATIVE_ENDIAN;
    snprintf(tpr->name, TPR_NAME_SIZE, "TPR_%" PRIx64 "-%" PRIx64 , addr, (addr+size));

    memory_region_init_io(&tpr->region, NULL, &tpr->ops, tpr, tpr->name, size);
    // might need _overlap variant if we set watch regions on memory-mapped devices. CHECK!
    memory_region_add_subregion(sysmem, addr, &tpr->region);

    if (NULL == (trapped_physregions = g_list_append(trapped_physregions, tpr))) {
        memory_region_del_subregion(sysmem, &tpr->region);
        g_free(tpr);
    }
}

static void util_trapped_physregion_remove(uint64_t addr, uint64_t size)
{
    GList *iterator;
    TrappedPhysRegion *tpr;
    MemoryRegion *sysmem = get_system_memory();

    for(iterator = trapped_physregions; iterator; iterator = iterator->next) {
        tpr = iterator->data;

        if (tpr->region.addr == addr && tpr->region.size == size) {
            printf("removing trapped physregion '%" PRIx64 "-%" PRIx64 "'\n", addr, (addr + size));
            trapped_physregions = g_list_delete_link(trapped_physregions, iterator);
            memory_region_del_subregion(sysmem, &tpr->region);
            g_free(tpr);
            return;
        }
    }

    printf("could not remove trapped physregion '%" PRIx64 "-%" PRIx64 "'\n", addr, (addr + size));
}

#ifdef LUAQEMU_DEBUG
static void lua_stackdump(lua_State *L)
{
    int i;
    int top = lua_gettop(L);
    printf("lua stack:\n");
    for (i = 1; i <= top; i++) {  /* repeat for each level */
        int t = lua_type(L, i);
        switch (t) {
            case LUA_TSTRING:  /* strings */
                printf("> '%s'", lua_tostring(L, i));
                break;
            case LUA_TBOOLEAN:  /* booleans */
                printf(lua_toboolean(L, i) ? "true" : "false");
                break;
            case LUA_TNUMBER:  /* numbers */
                printf("> %g", lua_tonumber(L, i));
                break;
            default:  /* other values */
                printf("> %s", lua_typename(L, t));
                break;
        }
        printf("\n");  /* put a separator */
    }
    printf("<- SP\n");  /* end the listing */
}
#else
static void lua_stackdump(lua_State *L) {}
#endif /* LUAQEMU_DEBUG */
 
static void lua_get_global(const char *name, int error)
{
    lua_getglobal(lua_state, name);
    if (error && lua_isnil(lua_state, -1)) {
        error_report("error getting '%s'\n", name);
        exit(1);
    }
}

static void lua_get_field(const char *name, int error)
{
    lua_pushstring(lua_state, name);
    lua_gettable(lua_state, -2); /* get table[name] */

    if (error && lua_isnil(lua_state, -1)) {
        error_report("error getting '%s'\n", name);
        exit(1);
    }
}

/* the following is reused from lua 5.2 */
#if !defined(LUA_IEEEENDIAN)    /* { */
#define LUAI_EXTRAIEEE  \
  static const union luai_Cast ieeeendian = {-(33.0 + 6755399441055744.0)};
#define LUA_IEEEENDIANLOC       (ieeeendian.l_p[1] == 33)
#else
#define LUA_IEEEENDIANLOC       LUA_IEEEENDIAN
#define LUAI_EXTRAIEEE          /* empty */
#endif                          /* } */

#if !defined(lua_number2int32) /* { */

union luai_Cast { double l_d; uint32_t l_p[2]; };

#define lua_number2int32(i,n,t) \
  { LUAI_EXTRAIEEE \
    volatile union luai_Cast u; u.l_d = (n) + 6755399441055744.0; \
    (i) = (t)u.l_p[LUA_IEEEENDIANLOC]; }

#define lua_number2unsigned(i,n)        lua_number2int32(i, n, uint64_t)
#endif                          /* } */

static uint64_t lua_get_unsigned(const char *name, int error)
{
    uint64_t res;
    double d;
    lua_get_field(name, error);
    d = lua_tonumber(lua_state, -1);

    lua_number2unsigned(res, d);
    debug_print("'%s'\t-> 0x%" PRIx64 "\n", name, res);

    lua_pop(lua_state, 1);
    return res;
}

static const char * lua_get_string(const char *name, int error) {
    const char *res;

    lua_get_field(name, error);
    res = lua_tostring(lua_state, -1);
    lua_pop(lua_state, 1);

    if (res) debug_print("'%s'\t-> %s\n", name, res);

    return res;
}

static int lua_get_boolean(const char *name, int error) {
    int res = 0;

    lua_get_field(name, error);
    res = lua_toboolean(lua_state, -1);
    lua_pop(lua_state, 1);

    debug_print("'%s'\t-> %s\n", name, res ? "true" : "false");

    return res;
}

static void add_memory_region(MemoryRegion *sm)
{
    hwaddr region_start = 0;
    uint64_t region_size = 0;
    const char *region_name = NULL;

    MemoryRegion *memory_region = NULL;

    if (!lua_istable(lua_state, -1)) {
        error_report("'%s' is not a valid table", lua_tostring(lua_state, -2));
        exit(3);
    }
    region_start = lua_get_unsigned("start", THROW_ERROR);
    region_size  = lua_get_unsigned("size", THROW_ERROR);
    region_name  = lua_get_string("name", THROW_ERROR);
    printf("region '%s' 0x%" PRIx64 " -> 0x%" PRIx64 "\n", region_name, region_start, region_start + region_size);

    memory_region = g_new(MemoryRegion, 1);
    memory_region_allocate_system_memory(memory_region, NULL, region_name, region_size);
    memory_region_add_subregion(sm, region_start, memory_region);
}

static void init_memory_regions(void)
{
    MemoryRegion *sysmem = get_system_memory();
    lua_get_global("memory_regions", THROW_ERROR);
    if (!lua_istable(lua_state, -1)) {
        error_report("no valid memory regions table found\n");
        exit(2);
    }

    /* we push nil on the stack so we know our list end is reached
       so at -1 we will have nil and at -2 our table */
    lua_pushnil(lua_state);
    while (lua_next(lua_state, -2)) {
        printf("adding memory region '%s'\n", lua_tostring(lua_state, -2));
        /*printf("%s - %s\n",
              lua_typename(lua_state, lua_type(lua_state, -2)),
              lua_typename(lua_state, lua_type(lua_state, -1))); */

        add_memory_region(sysmem);
        lua_pop(lua_state, 1);
    }
}

static void load_flat_file(const char *file_path, hwaddr start, uint64_t size)
{
    char *fn = NULL;
    if (NULL == (fn = qemu_find_file(QEMU_FILE_TYPE_BIOS, file_path))) {
        error_report("Couldn't find rom image '%s'.", file_path);
        exit(4);
    }

    // TODO: handle max_size argument properly
    if (0 > load_image_targphys(fn, start, size)) {
        error_report("Couldn't map file to memory\n");
        exit(5);
    }
    g_free(fn);
}

static void load_arm_elf(const char *file_path)
{
    int elf_machine = EM_ARM; /* TODO: why does this even matter here? */
    uint64_t elf_entry, elf_low_addr, elf_high_addr;
    bool elf_is64;
    union {
        Elf32_Ehdr h32;
        Elf64_Ehdr h64;
    } elf_header;

    int ret = -1;
    int data_swab = 0;
    bool big_endian;
    Error *err = NULL;

    load_elf_hdr(file_path, &elf_header, &elf_is64, &err);

    if (err) {
        error_report("couldn't load '%s'", file_path);
        exit(6);
    }

    if (elf_is64) {
        big_endian = elf_header.h64.e_ident[EI_DATA] == ELFDATA2MSB;
    } else {
        big_endian = elf_header.h32.e_ident[EI_DATA] == ELFDATA2MSB;
        if (big_endian) {
            if (!(bswap32(elf_header.h32.e_flags) & EF_ARM_BE8)) {
                data_swab = 2;
            }
        }
    }

    ret = load_elf(file_path, NULL, NULL, &elf_entry, &elf_low_addr,
                   &elf_high_addr, big_endian, elf_machine, 1, data_swab);

    if (ret <= 0) {
        error_report("Couldn't load elf image from '%s'", file_path);
        exit(7);
    }
    printf("ELF entry is at: 0x%lu\n", elf_entry);
}

static void add_file(void)
{
    hwaddr mapping_start = 0;
    uint64_t mapping_size = 0;
    const char *mapping_type = NULL;
    const char *mapping_fn = NULL;

    if (!lua_istable(lua_state, -1)) {
        error_report("'%s' is not a valid table", lua_tostring(lua_state, -2));
        exit(3);
    }
    mapping_fn    = lua_get_string("name", THROW_ERROR);
    mapping_type  = lua_get_string("type", NOTHROW_ERROR); /* we could also match the file extension here */

    if (!strcasecmp(mapping_fn, "kernel")) {
        if (!luastate.machine->kernel_filename) {
            error_report("-kernel is empty");
            exit(8);
        }
        mapping_fn = luastate.machine->kernel_filename;
    }

    if (mapping_type && !strcasecmp(mapping_type, "elf")) {
        load_arm_elf(mapping_fn);
    } else {
        mapping_start = lua_get_unsigned("start", THROW_ERROR);
        mapping_size  = lua_get_unsigned("size", THROW_ERROR);
        printf("trying to flat load file '%s' to 0x%" PRIx64 " (0x%" PRIx64 ")\n", mapping_fn, mapping_start, mapping_size);
        load_flat_file(mapping_fn, mapping_start, mapping_size);
    }
}

static void init_file_mappings(void)
{
    lua_get_global("file_mappings", THROW_ERROR);
    if (!lua_istable(lua_state, -1)) {
        error_report("no valid file mappings table found\n");
        return;
    }

    /* we push nil on the stack so we know our list end is reached
       so at -1 we will have nil and at -2 our table */
    lua_pushnil(lua_state);
    while (lua_next(lua_state, -2)) {
        printf("adding file mapping '%s'\n", lua_tostring(lua_state, -2));
        /*printf("%s - %s\n",
              lua_typename(lua_state, lua_type(lua_state, -2)),
              lua_typename(lua_state, lua_type(lua_state, -1))); */

        add_file();
        lua_pop(lua_state, 1);
    }
}

/* ============ keyword handling =========== */

static void init_reset_addr(int type)
{
    double d = 0;
    uint64_t addr;
    ARMCPU *cpu = ARM_CPU(luastate.cs);

    if (type != LUA_TNUMBER) {
        return;
    }
    d = lua_tonumber(lua_state, -1);
    lua_number2unsigned(addr, d);

    printf("reset address is: 0x%" PRIx64 "\n", addr);
    /* we abuse rvbar even when not being on aarch64 */
    cpu->rvbar = addr;

    return;
}

/* target/arm/cpu.h */
static void init_cpu_env_registers(void)
{
    int reg_i, reg_v = 0;
    char reg_s[4] = {0};

    lua_get_field("regs", 0);
    if (lua_isnil(lua_state, -1)) {
        error_report("no cpu register initialization");
        lua_pop(lua_state, 1);
        return;
    }

    if (lua_type(lua_state, -1) != LUA_TTABLE) {
        error_report("cpu registers are not a valid table");
        exit(9);
    }

    /* TODO address todo for get_field and get_* API and simplify this code */
    for (reg_i = 0; reg_i < sizeof(luastate.cpu->env.regs) / sizeof(*(luastate.cpu->env.regs)); reg_i++) {
        snprintf(reg_s, sizeof(reg_s), "r%d", reg_i);
        lua_pushstring(lua_state, reg_s);
        lua_gettable(lua_state, -2); /* get table[name] */

        if (lua_isnil(lua_state, -1)) {
            lua_pop(lua_state, 1);
            continue;
        } else {
            reg_v = lua_tointeger(lua_state, -1);
            debug_print("'%s' -> %x\n", reg_s, reg_v);
            luastate.cpu->env.regs[reg_i] = reg_v;
        }
        lua_pop(lua_state, 1);
    }

    lua_pop(lua_state, 1);
}

static void cpu_stuck_callback(const CPUState *cpu)
{
    vm_stop(RUN_STATE_PAUSED);

    /* get the function reference and push it to the stack */
    lua_rawgeti(lua_state, LUA_REGISTRYINDEX, luastate.stuck_state_cb);
    lua_stackdump(lua_state);
    if (lua_pcall(lua_state, 0, 0, 0)) {
        error_report("failed to call stuck callback (%d): %s\n", luastate.stuck_state_cb, lua_tostring(lua_state, -1));
    }
}

void lua_cpu_exec_insn_callback(uint64_t pc, uint64_t insn)
{
    if (luastate.exec_insn_cb == 0) return; /* this way we don't need to evaluate any state in QEMU core code */

    /* get the function reference and push it to the stack */
    lua_rawgeti(lua_state, LUA_REGISTRYINDEX, luastate.exec_insn_cb);
    lua_pushinteger(lua_state, pc);
    lua_pushinteger(lua_state, insn);
    lua_stackdump(lua_state);
    if (lua_pcall(lua_state, 2, 0, 0)) {
        error_report("failed to call exec_insn callback (%d): %s\n", luastate.exec_insn_cb, lua_tostring(lua_state, -1));
    }
}

void lua_cpu_exec_block_callback(uint64_t pc)
{
    if (luastate.exec_block_cb == 0) return; /* this way we don't need to evaluate any state in QEMU core code */

    /* get the function reference and push it to the stack */
    lua_rawgeti(lua_state, LUA_REGISTRYINDEX, luastate.exec_block_cb);
    lua_pushinteger(lua_state, pc);
    lua_stackdump(lua_state);
    if (lua_pcall(lua_state, 1, 0, 0)) {
        error_report("failed to call exec_block callback (%d): %s\n", luastate.exec_block_cb, lua_tostring(lua_state, -1));
    }
}

void lua_cpu_post_exec_block_callback(uint64_t pc)
{
    if (luastate.exec_block_cb == 0) return; /* this way we don't need to evaluate any state in QEMU core code */

    /* get the function reference and push it to the stack */
    lua_rawgeti(lua_state, LUA_REGISTRYINDEX, luastate.post_exec_block_cb);
    lua_pushinteger(lua_state, pc);
    lua_stackdump(lua_state);
    if (lua_pcall(lua_state, 1, 0, 0)) {
        error_report("failed to call post_exec_block callback (%d): %s\n", luastate.post_exec_block_cb, lua_tostring(lua_state, -1));
    }
}

static void set_cpu_stuck_state_cb(void)
{
    printf("Found stuck state callback. Make sure to set \"stuck_max\" in env block.\n");
    luastate.cs->crs.state_cb = cpu_stuck_callback;
}

static void init_cpu_env(int type)
{
    ARMCPU *cpu = ARM_CPU(luastate.cs);
    uint64_t periph_base = 0;

    if (type != LUA_TTABLE) {
        return;
    }

    periph_base = lua_get_unsigned("periph_base", 0);
    if (periph_base != 0) {
        printf("setting peripheral base for cbar to %" PRIx64 "\n", periph_base);
        /* see d8ba780b6a17020aadea479ad96ed9fe3bb10661 and related commits from Peter Crosthwaite */
        if (arm_feature(&luastate.cpu->env, ARM_FEATURE_CBAR)) {
            object_property_set_int(OBJECT(luastate.cpu), periph_base, "reset-cbar", &error_fatal);
        }
    }
    if (cpu->rvbar) {
        cpu_set_pc(luastate.cs, cpu->rvbar);
    }
    object_property_set_bool(OBJECT(luastate.cpu), true, "realized", &error_fatal);

    luastate.cpu->env.thumb   = lua_get_boolean("thumb", 0);
    luastate.cs->crs.miss_max = lua_get_unsigned("stuck_max", 0);
    if (luastate.cs->crs.miss_max) {
        printf("waiting for max %" PRIu64 " cycles\n", luastate.cs->crs.miss_max);
    }

    init_cpu_env_registers();
}

/* TODO: do we want to replace init_fptr with a setter for the callback? */
typedef struct {
    char keyword[256];
    int *lref;
    void (*init_fptr)(void);
} cb_keyword_table_t;

static const cb_keyword_table_t cb_kwt[] =
{
    {"stuck_state_cb",     &luastate.stuck_state_cb, set_cpu_stuck_state_cb},
    {"exec_insn_cb",       &luastate.exec_insn_cb, NULL},
    {"exec_block_cb",      &luastate.exec_block_cb, NULL},
    {"post_exec_block_cb", &luastate.post_exec_block_cb, NULL},
    {{0, 0, 0}}
};

static void init_cpu_callbacks(int type)
{
    unsigned int n = sizeof(cb_kwt) / sizeof(*cb_kwt);
    int i = 0;

    if (type != LUA_TTABLE) {
        return;
    }

    for (;i < n; i++) {
        lua_get_field(cb_kwt[i].keyword, 0);
        if (lua_isnil(lua_state, -1)) {
            lua_pop(lua_state, 1);
            continue;
        }

        *(cb_kwt[i].lref) = luaL_ref(lua_state, LUA_REGISTRYINDEX);
        printf("found callback for %s (%d)\n", cb_kwt[i].keyword, *(cb_kwt[i].lref));
        if (cb_kwt[i].init_fptr) cb_kwt[i].init_fptr();
    }
}

typedef struct {
    char keyword[256];
    void (*fptr)(int);
} keyword_table_t;

static const keyword_table_t kwt[] =
{
    {"reset_pc", init_reset_addr},
    {"env", init_cpu_env},
    {"callbacks", init_cpu_callbacks},
    {{0, 0}}
};

static int handle_keyword(int type, const char *key)
{
    unsigned int n = sizeof(kwt) / sizeof(*kwt);
    int i = 0;
    for (;i < n; i++) {
        if (!strcmp(kwt[i].keyword, key)) {
            kwt[i].fptr(type);
            return 0;
        }
    }
    error_report("keyword '%s' not known", key);
    return -1;
}

static void init_cpu_state(void)
{
    int m_type = 0;
    const char *m_name = NULL;

    lua_get_global("cpu", NOTHROW_ERROR);
    if (!lua_istable(lua_state, -1)) {
        error_report("no valid cpu table found, you may want to define one\n");
        return;
    }

    /* we push nil on the stack so we know our list end is reached
       so at -1 we will have nil and at -2 our table */
    lua_pushnil(lua_state);
    while (lua_next(lua_state, -2)) {
        m_name = lua_tostring(lua_state, -2);
        m_type = lua_type(lua_state, -1);

        debug_print("keyword name: %s, type %s\n", m_name, lua_typename(lua_state, m_type));
        handle_keyword(m_type, m_name);

        lua_pop(lua_state, 1);
    }

}

/* ============ end keyword handling =========== */

/* ============== lua API functions ============= */

extern uint64_t lua_get_pc(void);
extern void lua_set_pc(uint64_t);
extern void lua_watchpoint_insert(uint64_t, uint64_t, int, watchpoint_cb);
extern void lua_watchpoint_remove(uint64_t, uint64_t, int);
extern void lua_breakpoint_remove(uint64_t);
extern void lua_breakpoint_insert(uint64_t, void (*)(void));
extern void lua_continue(void);
extern uint64_t lua_get_register(uint8_t);
extern void lua_set_register(uint8_t, uint64_t);
extern uint8_t lua_get_regcount(void);
extern void lua_trapped_physregion_add(uint64_t addr, uint64_t size, TprReadCb readCb, TprWriteCb writeCb);
extern void lua_trapped_physregion_remove(uint64_t addr, uint64_t size);

static inline uint64_t lua_current_pc(void) {
    return !is_a64(&luastate.cpu->env) ? luastate.cpu->env.regs[15] : luastate.cpu->env.pc;
}

void lua_watchpoint_insert(uint64_t addr, uint64_t size, int flags, watchpoint_cb func)
{
    util_watchpoint_insert(addr, size, flags, func);
}

void lua_watchpoint_remove(uint64_t addr, uint64_t size, int flags)
{
    util_watchpoint_remove(addr, size, flags);
}

/* we could store the callback function pointer directly here. however, to reuse the logic we
   already have wrt breakpoints table, we make use of the function value on the stack here,
   pop it, get a unique reference to it (luaL_ref) and reuse the same hash table.
 */
void lua_breakpoint_insert(uint64_t addr, void (*func)(void))
{
    int bp_func = luaL_ref(lua_state, LUA_REGISTRYINDEX);

    util_breakpoint_insert(addr, bp_func);
}

void lua_breakpoint_remove(uint64_t addr)
{
    util_breakpoint_remove(addr);
}

void lua_continue(void)
{
    vm_start();
}

uint64_t lua_get_pc(void)
{
    return lua_current_pc();
}

void lua_set_pc(uint64_t addr)
{
    if (!is_a64(&luastate.cpu->env)) {
        luastate.cpu->env.regs[15] = addr;
    } else {
        luastate.cpu->env.pc = addr;
    }
}

uint8_t lua_get_regcount(void)
{
    if (!is_a64(&luastate.cpu->env)) {
        return sizeof(luastate.cpu->env.regs) / sizeof(*(luastate.cpu->env.regs));
    } else {
        return sizeof(luastate.cpu->env.xregs) / sizeof(*(luastate.cpu->env.xregs));
    }
}

void lua_trapped_physregion_add(uint64_t addr, uint64_t size, TprReadCb readCb, TprWriteCb writeCb)
{
    util_trapped_physregion_add(addr, size, readCb, writeCb);    
}

void lua_trapped_physregion_remove(uint64_t addr, uint64_t size)
{
    util_trapped_physregion_remove(addr, size);
}

uint64_t lua_get_register(uint8_t reg)
{
    if (!is_a64(&luastate.cpu->env)) {
        if (reg >= sizeof(luastate.cpu->env.regs) / sizeof(*(luastate.cpu->env.regs))) {
            error_report("%s '%d' exceeds cpu registers", __func__, reg);
            return 0;
        }
        return luastate.cpu->env.regs[reg];
    } else {
        if (reg >= sizeof(luastate.cpu->env.xregs) / sizeof(*(luastate.cpu->env.xregs))) {
            error_report("%s '%d' exceeds cpu registers", __func__, reg);
            return 0;
        }
        return luastate.cpu->env.xregs[reg];
    }
}

void lua_set_register(uint8_t reg, uint64_t value)
{
    if (!is_a64(&luastate.cpu->env)) {
        if (reg >= sizeof(luastate.cpu->env.regs) / sizeof(*(luastate.cpu->env.regs))) {
            error_report("%s '%d' exceeds cpu registers", __func__, reg);
            return;
        }
        luastate.cpu->env.regs[reg] = value;
    } else {
        if (reg >= sizeof(luastate.cpu->env.xregs) / sizeof(*(luastate.cpu->env.xregs))) {
            error_report("%s '%d' exceeds cpu registers", __func__, reg);
            return;
        }
        luastate.cpu->env.xregs[reg] = value;
    }
    debug_print("%s r%d -> %" PRIx64 "\n", __func__, reg, value);
}


static inline int lua_memory_rw(target_ulong addr, uint8_t *buf, int len, bool is_write)
{
	CPUClass *cc = CPU_GET_CLASS(luastate.cs);
	if (cc->memory_rw_debug) {
		return cc->memory_rw_debug(luastate.cs, addr, buf, len, is_write);
	}
	return cpu_memory_rw_debug(luastate.cs, addr, buf, len, is_write);
}

uint8_t lua_read_byte(uint64_t);
uint16_t lua_read_word(uint64_t);
uint32_t lua_read_dword(uint64_t);
uint64_t lua_read_qword(uint64_t);
void lua_read_memory(uint8_t *, uint64_t, size_t);
void lua_write_byte(uint64_t, uint8_t);
void lua_write_word(uint64_t, uint16_t);
void lua_write_dword(uint64_t, uint32_t);
void lua_write_qword(uint64_t, uint64_t);
void lua_write_memory(uint64_t, uint8_t *, size_t);

void lua_write_memory(uint64_t addr, uint8_t *src, size_t len)
{
	lua_memory_rw(addr, src, len, 1);
}
void lua_write_byte(uint64_t addr, uint8_t value)
{
	lua_memory_rw(addr, (uint8_t *) &value, sizeof(value), 1);
}
void lua_write_word(uint64_t addr, uint16_t value)
{
	lua_memory_rw(addr, (uint8_t *) &value, sizeof(value), 1);
}
void lua_write_dword(uint64_t addr, uint32_t value)
{
	lua_memory_rw(addr, (uint8_t *) &value, sizeof(value), 1);
}
void lua_write_qword(uint64_t addr, uint64_t value)
{
	lua_memory_rw(addr, (uint8_t *) &value, sizeof(value), 1);
}
void lua_read_memory(uint8_t *dest, uint64_t addr, size_t size)
{
	lua_memory_rw(addr, dest, size, 0);
}
uint64_t lua_read_qword(uint64_t addr)
{
	uint64_t ret = 0;
	lua_memory_rw(addr, (uint8_t *) &ret, sizeof(ret), 0);
	return ret;
}
uint32_t lua_read_dword(uint64_t addr)
{
	uint32_t ret = 0;
	lua_memory_rw(addr, (uint8_t *) &ret, sizeof(ret), 0);
	return ret;
}
uint16_t lua_read_word(uint64_t addr)
{
	uint16_t ret = 0;
	lua_memory_rw(addr, (uint8_t *) &ret, sizeof(ret), 0);
	return ret;
}
uint8_t lua_read_byte(uint64_t addr)
{
	uint8_t ret = 0;
	lua_memory_rw(addr, &ret, sizeof(ret), 0);
	return ret;
}

/* ============== end lua API functions ============= */

/* ============ state change handling ============ */

static int trigger_breakpoint(int func)
{
    /* get the function reference and push it to the stack */
    lua_rawgeti(lua_state, LUA_REGISTRYINDEX, func);
    lua_stackdump(lua_state);
    if (lua_pcall(lua_state, 0, 0, 0)) {
        error_report("failed to execute breakpoint (%d): %s\n", func, lua_tostring(lua_state, -1));
        return -1;
    }

    return 0;
}

static inline void handle_vm_state_breakpoint(uint64_t pc)
{
    int bp_func;

    bp_func = GPOINTER_TO_INT(g_hash_table_lookup(breakpoints, GUINT_TO_POINTER(pc)));
    if (bp_func) {
        trigger_breakpoint(bp_func);
        /* we need to remove the breakpoint, otherwise we trigger again when
           continuing execution. gdb does this by setting a breakpoint on the next
           instruction and then reinsterting it. we don't need to do this if pc
           was changed by the breakpoint however.
        */
        if (pc == lua_current_pc()) {
            cpu_breakpoint_remove(luastate.cs, pc, BP_LUA);
            /* a single step will raise another DEBUG exception after each instruction.
               we catch this so that we reinsert the breakpoint again
             */
            luastate.bp_pc = pc;
            luastate.bp_pc_ptr = &luastate.bp_pc;
            cpu_single_step(luastate.cs, 1);
        }
        // TODO: introduce flag potentially to control this behavior
        tb_flush(luastate.cs);
    } else {
        /* if our breakpoint doesn't trigger, but we trigger a DEBUG exception there are two
           cases: 1) we dont handle this state yet (e.g. watchpoints) 2) we single stepped.
           we use luastate.bp_pc_ptr to know whether there was a lua breakpoint set before.
           otherwise the pointer is NULL. this way we can prevent vm_start()'ing every time
           when hitting a gdb breakpoint.
         */
        if (!luastate.bp_pc_ptr) {
            return;
        }

        cpu_single_step(luastate.cs, 0);
        cpu_breakpoint_insert(luastate.cs, luastate.bp_pc, BP_LUA, NULL);
        vm_start(); /* this is expensive */
        luastate.bp_pc_ptr = NULL;
    }
}

static inline void handle_vm_state_watchpoint(CPUWatchpoint *wpt, watchpoint_t *owp)
{
    GList *iterator;
    watchpoint_t *wp;

    if (luastate.old_wp_ptr && owp && luastate.old_wp_ptr == owp) {
        cpu_single_step(luastate.cs, 0);
        cpu_watchpoint_insert(luastate.cs, owp->addr, owp->len, owp->flags, NULL);
        vm_start(); /* this is expensive */
        return;
    }
    for(iterator = watchpoints; iterator; iterator = iterator->next) {
        wp = iterator->data;
        if (wp->addr == wpt->vaddr && wp->len == wpt->len && (wp->flags & wpt->flags)) {

            watchpoint_args_t arg;
            arg.len = wpt->len;
            arg.flags = wpt->flags;
            arg.addr = wpt->vaddr;
            wp->fptr(&arg);

            cpu_watchpoint_remove(luastate.cs, wp->addr, wp->len, wp->flags);
            luastate.old_wp_ptr = wp;
            cpu_single_step(luastate.cs, 1);
            // TODO: introduce flag potentially to control this behavior
            tb_flush(luastate.cs);
            return;
        }
    }
}

static void lua_vm_state_change(void *opaque, int running, RunState state)
{
    /* we remember the old pc value to make sure that
       we notice if the pc was changed in the breakpoint
       handler itself
    */
    uint64_t old_pc = lua_current_pc();

    if (running) {
        return;
    }
    debug_print("VM state change at: %" PRIx64 "\n", old_pc);

    switch (state) {
        case RUN_STATE_DEBUG:
            /* when hitting a watchpoint, we temporarily remove the cpu watchpoint and do a single step.
               this has the side effect that luastate contains a pointer to our old watchpoint and that
               qemu will raise another debug exception, which we abuse to reinsert the watchpoint. as this
               can originate from a breakpoint or a watchpoint (we use the same technique), we only have
               old_wp_ptr to notice this
            */
            if (luastate.old_wp_ptr) {
                handle_vm_state_watchpoint(NULL, luastate.old_wp_ptr);
                luastate.old_wp_ptr = NULL;
                return;
            }
            if (luastate.cs->watchpoint_hit) {
                /* as our lua engine state change handler is always called after the gdbstub
                   we set it always to NULL here and removed this from gdbstub
                */
                handle_vm_state_watchpoint(luastate.cs->watchpoint_hit, NULL);
                luastate.cs->watchpoint_hit = NULL;
            } else {
                handle_vm_state_breakpoint(old_pc);
            }
            break;
        case RUN_STATE_INTERNAL_ERROR:
            break;
        case RUN_STATE_IO_ERROR:
            break;
        case RUN_STATE_PAUSED:
            break;
        case RUN_STATE_RUNNING:
            break;
        case RUN_STATE_RESTORE_VM:
        case RUN_STATE_SAVE_VM:
            break;
        case RUN_STATE_SHUTDOWN:
            break;
        case RUN_STATE_WATCHDOG:
            break;
        default:
            debug_print("RunState: %d\n", state);
            break;
    }
    /* qapi-types.h */
}

/* assuming our lua code does C.lua_breakpoint_insert() as part of the code
   that is evaluated during the initial pcall, we have a problem. specifically,
   since we intiliaze the machine as well from lua_init (so later), the cpu
   breakpoints list isn't initialized yet so that we can't insert cpu breakpoints.
   to workaround this, we add all remaining (those that are in our hash table, but not
   in the cpu list) breakpoints to the cpu list after the vm state is initialized.
 */
static void add_cpu_breakpoints(gpointer key, gpointer value, gpointer user_data)
{
    CPUBreakpoint *bp;
    QTAILQ_FOREACH(bp, &luastate.cs->breakpoints, entry) {
        if (bp->pc == GPOINTER_TO_UINT(key)) {
            return; /* the breakpoint is already part of the list */
        }
    }
    cpu_breakpoint_insert(luastate.cs, GPOINTER_TO_UINT(key), BP_LUA, NULL);
}

static void init_vm_states(void)
{
    int bp_func;

    qemu_add_vm_change_state_handler(lua_vm_state_change, NULL);
    lua_get_global("breakpoints", NOTHROW_ERROR);
    if (!lua_istable(lua_state, -1)) {
        error_report("%s breakpoints is no table", __func__);
        return;
    }

    lua_stackdump(lua_state);
    lua_pushnil(lua_state);
    while (lua_next(lua_state, -2)) {
        lua_stackdump(lua_state);
        /* we can't use the function pointer directly here
           instead we pop the value from the stack, add it to the registry
           and work with a unique reference to it
        */
        bp_func = luaL_ref(lua_state, LUA_REGISTRYINDEX);
        lua_pushnil(lua_state);
        util_breakpoint_insert(lua_tointeger(lua_state, -2), bp_func);

        lua_pop(lua_state, 1);
    }
    printf("added %d breakpoints...\n", g_hash_table_size(breakpoints));
}

/* ============ end state change handling ============ */

static void init_luastate(MachineState *machine)
{
    ARMCPU *cpu;
    ObjectClass *cpu_oc;
    CPUState *cs;

    cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, machine->cpu_model);
    if (!cpu_oc) {
        error_report("machine \"%s\" not found, exiting\n", machine->cpu_model);
        exit(1);
    }

    cpu = ARM_CPU(object_new(object_class_get_name(cpu_oc)));
    cs = CPU(cpu);

    luastate.cpu = cpu;
    luastate.cs = cs;
    luastate.machine = machine;
    luastate.bp_pc = 0;
    luastate.bp_pc_ptr = NULL;
    luastate.old_wp_ptr = NULL;

    g_hash_table_foreach(breakpoints, add_cpu_breakpoints, NULL);
}

static void lua_init(MachineState *machine)
{
    breakpoints = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!lua_script) {
        error_report("no lua script argument supplied (-lua)");
        exit(1);
    }

    lua_state = luaL_newstate();
    if (lua_state == NULL) {
        error_report("could not initialize LuaJIT (%s)", strerror(errno));
        exit(1);
    }
    luaL_openlibs(lua_state);

    if (luaL_loadfile(lua_state, lua_script)) {
        error_report("failed to load Lua script: %s", lua_tostring(lua_state, -1));
    }
    /* execute lua script */
    if (lua_pcall(lua_state, 0, 0, 0)) {
        error_report("failed to execute Lua script: %s", lua_tostring(lua_state, -1));
        exit(1);
    }

    if (NULL == machine->cpu_model) {
        lua_get_global("machine_cpu", THROW_ERROR);
        machine->cpu_model = lua_tostring(lua_state, -1);
        printf("found machine cpu type: %s\n", machine->cpu_model);
    }

    init_memory_regions();
    init_luastate(machine);

    init_file_mappings();
    init_cpu_state();
    init_vm_states();

    lua_getglobal(lua_state, "post_init");
    if (lua_isnil(lua_state, -1)) {
        printf("no post_init function to be called\n");
    }

    if (lua_pcall(lua_state, 0, 0, 0)) {
        printf("problem during post_init function call: %s\n", lua_tostring(lua_state, -1));
    }
}

static void lua_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Lua ARM Meta Machine";
    mc->init = lua_init;
}

static const TypeInfo lua_machine_type = {
    .name = MACHINE_TYPE_NAME("luaarm"),
    .parent = TYPE_MACHINE,
    .class_init = lua_class_init,
};

static void lua_machine_init(void)
{
    type_register_static(&lua_machine_type);
}

type_init(lua_machine_init)
