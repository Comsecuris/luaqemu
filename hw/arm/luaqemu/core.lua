-- Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)
-- Utility/API definitions for luaqemu
--[[
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
--]]

ffi = require("ffi")
C = ffi.C

ffi.cdef[[
/* typedefs */
typedef uint64_t hwaddr;

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

/******************************************************************************/

int printf(const char *fmt, ...);

/* execution */
void lua_continue(void);

/* breakpoints */
void lua_breakpoint_insert(uint64_t, void (*)(void));
void lua_breakpoint_remove(uint64_t);

/* watchpoints  - they trigger *before* the read/write happens */
void lua_watchpoint_insert(uint64_t, uint64_t, int flags, watchpoint_cb cb);
void lua_watchpoint_remove(uint64_t, uint64_t, int flags);

/* trapped physical regions */
void lua_trapped_physregion_add(uint64_t addr, uint64_t size,
				TprReadCb readCb, TprWriteCb writeCb);
void lua_trapped_physregion_remove(uint64_t addr, uint64_t size);

/* registers */
void lua_set_pc(uint64_t);
uint64_t lua_get_pc(void);
uint64_t lua_get_register(uint8_t);
void lua_set_register(uint8_t, uint64_t value);
uint8_t lua_get_regcount(void);

/* memory */
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
]]


----- wrappers for internal api
-------- control flow
function lua_continue()
    C.lua_continue()
end
-------- trap regions
function lua_trapped_physregion_add(addr, size, readcb, writecb)
    C.lua_trapped_physregion_add(addr, size, readcb, writecb)
end
function lua_trapped_physregion_remove(addr, size)
    C.lua_trapped_physregion_remove(addr, size)
end
-------- watchpoints
WP_MEM_READ = 0x1
WP_MEM_WRITE = 0x2
WP_MEM_ACCESS = 0x3
function lua_watchpoint_insert(addr, size, flags, fptr)
    C.lua_watchpoint_insert(addr, size, flags, fptr)
end
function lua_watchpoint_remove(addr, size, flags)
    C.lua_watchpoint_remove(addr, size, flags)
end
function lua_wp_flags_str(f)
    local bit = require("bit")
    local band = bit.band
    local access = ""
    if band(f, WP_MEM_READ) then
        access = access .. "r"
    end
    if band(f, WP_MEM_WRITE) then
        access = access .. "w"
    end
    if band(f, WP_MEM_ACCESS) then
        access = access .. "a"
    end

    return access
end
-------- breakpoints
function lua_breakpoint_remove(addr)
    C.lua_breakpoint_remove(addr)
end
function lua_breakpoint_insert(addr, fptr)
    C.lua_breakpoint_insert(addr, fptr)
end

function lua_bp()
-- this is a globally defined dummy function
end
-------- registers
function lua_set_pc(val)
    C.lua_set_pc(val)
end
function lua_get_pc()
    return ffi.cast('uint64_t', C.lua_get_pc())
end
function lua_get_register(reg)
    return ffi.cast('uint64_t', C.lua_get_register(reg))
end
function lua_set_register(reg, value)
    C.lua_set_register(reg, value)
end
-------- read memory
function lua_read_memory(buf, addr, size)
    C.lua_read_memory(buf, addr, size)
end
function lua_read_qword(addr)
    return ffi.cast('uint64_t', C.lua_read_qword(addr))
end
function lua_read_dword(addr)
    return ffi.cast('uint32_t', C.lua_read_dword(addr))
end
function lua_read_word(addr)
    return ffi.cast('uint16_t', C.lua_read_word(addr))
end
function lua_read_byte(addr)
    return ffi.cast('uint8_t', C.lua_read_byte(addr))
end
-------- write memory
function lua_write_memory(addr, buf, size)
    local b = ffi.new('uint8_t[?]', #buf)
    ffi.copy(b, buf)
    C.lua_write_memory(addr, b, size)
end
function lua_write_qword(addr, value)
    C.lua_write_qword(addr, value)
end
function lua_write_dword(addr, value)
    C.lua_write_dword(addr, value)
end
function lua_write_word(addr, value)
    C.lua_write_word(addr, value)
end
function lua_write_byte(addr, value)
    C.lua_write_byte(addr, value)
end

-------- convenience helpers
function lua_set_all_registers(regs)
    for reg, val in pairs(regs) do
        C.lua_set_register(reg - 1, val)
    end
end

function lua_get_all_registers()
    local regs = {}
    n_regs = C.lua_get_regcount()
    for reg=0, n_regs-1 do
        value = C.lua_get_register(reg)
        table.insert(regs, value)
    end
    return regs
end

function lua_read_mem(addr, len)
    local buf = ffi.new('uint8_t[?]', len)
    C.lua_read_memory(buf, addr, len)
    return ffi.string(buf, len)
end

function get_string(addr)
    local t = {}
    local i = 0
    while true do
        local b = C.lua_read_byte(addr + i)
        if b == 0 then
            return ffi.string(table.concat(t,""))
        end
        t[i + 1] = string.char(b)
        i = i + 1
    end
end

function write_file(f, buf)
    local f = assert(io.open(f, "wb"))
    local t = f:write(buf)
    f:close()
end

function read_file(f)
    local f = assert(io.open(f, "rb"))
    local t = f:read("*all")
    f:close()
    return t
end

-- bit manipulation
function pack_32bit(i)
    local hihi = bit.band(bit.arshift(i, 24), 0xff)
    local hilo = bit.band(bit.arshift(i, 16), 0xff)
    local lohi = bit.band(bit.arshift(i, 8), 0xff)
    local lolo = bit.band(i, 0xff)
    return string.char(lolo, lohi, hilo, hihi)
end

-- courtesy of Michal Kottman
function string.tohex(str)
    return (str:gsub('.', function (c)
            return string.format('%02X', string.byte(c))
    end))
end

-- slightly modified from lua-users.org
function hex_dump(buf,prefix,first,last)
    local function align(n) return math.ceil(n/16) * 16 end
    for i = (align((first or 1)-16)+1), align(math.min(last or #buf,#buf)) do
        if (i-1) % 16 == 0 then
            io.write(string.format('%08X  ', (prefix or 0) + i-1))
        end
        io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
        if i %  8 == 0 then
            io.write(' ')
        end
        if i % 16 == 0 then
            io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' )
        end
    end
end
