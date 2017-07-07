-- Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)
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

local ffi = require("ffi")
local bit = require("bit")
local arm = require("hw.arm.luaqemu.capstone.arm")
local x86 = require("hw.arm.luaqemu.capstone.x86")

local arm = require("hw.arm.luaqemu.capstone_core")

local cs = ffi.load('capstone')

capstone = {}
capstone.cs = cs

-- tested
function capstone.cs_version(major, minor)
    return cs.cs_version(major, minor)
end

function capstone.cs_support(query)
    return cs.cs_support(query)
end

-- tested
function capstone.cs_open(arch, mode)
    local handle = ffi.new('csh[1]')
    local err = cs.cs_open(arch, mode, handle)
    capstone.handle = handle

    if err ~= cs.CS_ERR_OK then
        C.printf(cs.cs_strerror(err))
    end
    return err
end

-- tested
function capstone.cs_close()
    cs.cs_close(capstone.handle)
end

-- tested
-- NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
-- so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
-- even before cs_open()
function capstone.cs_option(t, value)
    return cs.cs_option(capstone.handle[0], t, value)
end

-- tested
function capstone.cs_errno()
    return cs.cs_errno(capstone.handle[0])
end

-- tested
function capstone.cs_strerror(code)
    return cs.cs_strerror(code)
end

-- tested
function capstone.cs_disasm(code, code_size, address, count)
    local insn = ffi.new('cs_insn*[1]')
    local count = cs.cs_disasm(capstone.handle[0], code, code_size, address, count, insn)
    return count, insn[0]
end

-- tested
function capstone.cs_free(insn, count)
    cs.cs_free(insn, count)
end

function capstone.cs_malloc()
    return cs.cs_malloc(capstone.handle[0])
end

function capstone.cs_disasm_iter(code, size, address)
    local insn = ffi.new('cs_insn[1]')
    local ret = cs.cs_disasm_iter(capstone.handle[0], code, size, address, insn)
    return ret, insn
end

-- tested
function capstone.cs_insn_name(insn_id)
    local ret = cs.cs_insn_name(capstone.handle[0], insn_id)
    if ret ~= nil then return ffi.string(ret) else return "" end
end

-- tested
function capstone.cs_reg_name(reg_id)
    local ret = cs.cs_reg_name(capstone.handle[0], reg_id)
    if ret ~= nil then return ffi.string(ret) else return "" end
end

function capstone.cs_group_name(group_id)
    local ret = cs.cs_group_name(capstone.handle[0], group_id)
    if ret ~= nil then return ffi.string(ret) else return "" end
end

-- NOTE: this API is only valid when CS_OPT_DETAIL option is ON (which is OFF by default).
function capstone.cs_insn_group(insn, group_id)
    return cs.cs_insn_group(capstone.handle[0], insn, group_id)
end

-- NOTE: this API is only valid when CS_OPT_DETAIL option is ON (which is OFF by default).
function capstone.cs_reg_read(insn, reg_id)
    return cs.cs_reg_read(capstone.handle[0], insn, reg_id)
end

-- NOTE: this API is only valid when CS_OPT_DETAIL option is ON (which is OFF by default).
function capstone.cs_reg_write(insn, reg_id)
    return cs.cs_reg_write(capstone.handle[0], insn, reg_id)
end

-- NOTE: this API is only valid when CS_OPT_DETAIL option is ON (which is OFF by default).
-- tested
function capstone.cs_op_count(insn, op_type)
    return cs.cs_op_count(capstone.handle[0], insn, op_type)
end

-- NOTE: this API is only valid when CS_OPT_DETAIL option is ON (which is OFF by default).
-- tested
function capstone.cs_op_index(insn, op_type, position)
    return cs.cs_op_index(capstone.handle[0], insn, op_type, position)
end
