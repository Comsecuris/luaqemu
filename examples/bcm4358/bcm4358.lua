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

require('hw.arm.luaqemu.core')

machine_cpu = 'cortex-r5'

memory_regions = {
    region_rom = {
        name = 'mem_rom',
        start = 0x0,
        size = 0x180000
    },
    region_ram = {
        name = 'mem_ram',
        start = 0x180000,
        size = 0xC0000
    },
}

file_mappings = {
    main_rom = {
        name = 'examples/bcm4358/bcm4358.rom.bin',
        start = 0x0,
        size = 0x180000
    },
    main_ram = {
        name = 'kernel',
        start = 0x180000,
        size = 786432,
    }
}

function lua_stuck_cb()
    C.printf("CPU is stuck around 0x%x\n", lua_get_pc())
    local rregs = lua_get_all_registers()
    for idx, val in ipairs(rregs) do
        C.printf("r%d\t0x%x\n", ffi.new('int',idx-1), val);
    end
    -- lua_continue()
end

cpu = {
    env = {
        thumb = true,
        stuck_max = 200000,
        stuck_cb = lua_stuck_cb,
        regs = {}
    },
    reset_pc = 0
}


function bp_patch_18000000()
    lua_write_word(0x180000FC, 1);
    lua_continue()
end

i=0
function bp_mod_v15()
    i = i+1
    lua_set_register(3, 1)
    if i == 0xf then
        lua_set_register(3, 0xf)
    end
    lua_continue()
end

function bp_mod_fff0()
    print("FFF0 check")
    lua_set_register(3, 0x83e00)
    lua_continue()
end

-- this is unused and we ignore all the init functions, because they are gone in the PATCHRAM that we currently use
function bp_skip_00188CF2()
    --lua_set_pc(0x00188CF6)
    lua_set_pc(0x00188D00)
    lua_continue()
end

function bp_log_formatted()
    print(get_string(lua_get_register(4)-lua_get_register(0)))
    lua_continue()
end

function call_wlc_recvdata_tdls()
    local wlc_recv = 0x0019B698
    local wlc_info = 0x001ff418 -- this is allocated very early on and at a static location wl_info lives at 0x22DDB0
    local packet_p = 0x1E3410 -- scratch space TODO: use malloc here instead
    local packet_raw = 0x1E3510 -- scratch space
    local frame_len = 229

    -- load ramdump
    local buf = read_file('./examples/bcm4358/bcm4358.ramdump.bin')
    lua_write_memory(0x180000, buf, #buf)

    lua_write_byte(packet_p + 0, 0x1);         -- unkn
    lua_write_byte(packet_p + 1, 0x0);         -- unkn
    lua_write_byte(packet_p + 2, 0x1);         -- refcnt
    lua_write_byte(packet_p + 3, 0x1);         -- alloc status
    lua_write_byte(packet_p + 4, 0x0);         -- unkn
    lua_write_byte(packet_p + 5, 0x0);         -- unkn
    lua_write_byte(packet_p + 6, 0x0);         -- unkn
    lua_write_byte(packet_p + 7, 0x0);         -- unkn
    lua_write_dword(packet_p + 8, packet_raw-0x28); -- data pointer (-0x28 to account for wrxh)
                                                    -- this works well enough, because this area is nulled
    lua_write_word(packet_p + 0xc, frame_len); -- frame length
    lua_write_word(packet_p + 0xe, 0x0)        -- unkn

    local buf = read_file('./examples/bcm4358/packets/data/tlds/1.tdls_setup-conf.raw')
    lua_write_memory(packet_raw, buf, #buf)

    hex_dump(lua_read_mem(packet_p, 0xf), packet_p)
    print("------")
    hex_dump(lua_read_mem(packet_raw, #buf), packet_raw)

    print("call_wlc_recv()")
    lua_set_register(0, wlc_info)
    lua_set_register(1, packet_p)
    lua_set_register(14, 0x181BA7) -- endless loop

    lua_set_pc(wlc_recv)
    --lua_continue()
end

function bp_wfi_loop()
    print("WFI loop reached")
    add_malloc_breakpoints()
    call_wlc_recvdata_tdls()
end

function bp_pkt_free()
    C.printf("pktfree() called from 0x%x\n", lua_get_register(14));
    lua_set_pc(lua_get_register(14))
    lua_continue()
end

function bp_fix_core_settings()
    -- we could also initialize the registers on boot properly
    local ram_size = 0xc0000
    local ram_start = 0x180000
    local ram_end = 0x240000
    local core_base = 0x18002000
    local core_wrap = 0x18102000

    lua_set_register(5, ram_size)
    lua_set_register(6, ram_start)
    lua_set_register(7, ram_end)
    lua_set_register(8, core_base)
    lua_set_register(9, core_wrap)
    lua_continue()
end

-- this messes up the registers we set before in bp_fix_core_settings
-- for now we skip the function. i believe its operating on wrong data anyway right
-- so that its functionality is questionable
function bp_skip_btcm_something()
    lua_set_pc(0x00181DF6)
    lua_continue()
end

-- we should look at this function again at some point as it does give
-- hints on whats wrong during init. bp_fix_core_settings was caught with this
function bp_soc_sanity_checks_something()
    lua_set_pc(0x00188CF6)
    lua_continue()
end

function bp_si_findcoreidx()
    lua_set_pc(0x14D0E)
    lua_continue()
end

function bp_skip_init_excp_handler()
    lua_set_pc(0x001DC740)
    lua_continue()
end

function bp_module_register_something()
    print("bp_module_register_something() - we skip a substantial amount of code here not knowing what is wrong")
    lua_continue()
end

-- we overwrite tome before storage in a local variable as otherwise
-- frames that dont match our hwaddr and are not multicast would be tossed
function bp_fix_tome_ctl()
    lua_set_register(0, 0x1)
    lua_continue()
end
function bp_fix_tome_data()
    lua_set_register(0, 0x1)
    lua_set_register(6, 0x1)
    lua_continue()
end

-- 0x1 is not a correct value here, especially since it's read from that
-- location. using for now to progress though
function bp_fix_bsscfg_data()
    lua_set_register(0, 0x1)
    lua_continue()
end

-- i'm not sure which field is checked here
-- but we want to get around this error case and the flag is
-- otherwise not used by subsequent code. so we set the register
-- to prevent an early error-out
function bp_workaround_v25_pktfree_data()
    lua_set_register(1,0)
    lua_continue()
end

-- unclear what is checked here exactly
-- it looks like the peer connection status is checked, but we need to take a closer look
function bp_workaround_peer_connection_check_tdls()
    lua_set_register(1,1)
    lua_continue()
end

-- the pointer we pass here is not valid, but we just need to return
-- a non null pointer for the code to be happy
function bp_fix_peer_connection_tdls()
    lua_set_register(0,1)
    lua_continue()
end

-- the link-id check in the packet must match the link-id of the established
-- tdls tunnel. we always make validated_linkid return success to address this
-- because of where we do it, we'll still see the linkid error message
function bp_fix_linkid_check_tdls()
    lua_set_register(0,0)
    lua_set_pc(0x7E84E)
    lua_continue()
end

function bp_fix_hwaddr_check()
    lua_set_register(0,0)
    lua_continue()
end

function bp_wlc_recvfilter()
    lua_set_register(0, 0) -- accept frame
    lua_continue()
end

-- there's a check for a setting flag here
-- if we ignore this, we'll run into the following error:
-- wl0:wlc_tdls_rcv_action_frame(): TDLS is prohibited in ext cap.
function bp_fix_tdls_ext_cap()
    lua_set_register(2,0)
    lua_continue()
end

function bp_fix_bcmp_tdls()
    lua_set_register(0,0)
    lua_continue()
end

-- see 0019B2B0 and following basic block
function bp_fix_aosscresp_client_pre_checks()
    lua_set_pc(0x0019B2BA)
    lua_set_register(0, 4)
    lua_set_register(3, 0)
    lua_continue()
end

function bp_fix_assocresp_state()
    lua_set_pc(0x3E2F0)
end

function bp_fix_auth_bsscfg_check()
    lua_set_register(1,4)
    lua_set_pc(0x19B288) -- skip directly to the handling of wlc_authresp_client
    lua_continue()
end

function bp_fix_authresp_client_pre_checks()
    lua_set_pc(0x0003E9AC) -- we skip the check for the unsolicited response etc
end

function bp_fix_bsccfg_tdls_something()
    lua_set_register(3,0xffffffff)
    lua_continue()
end

-- we bypass the following check, not knowing what this is, but it's not related to the frame itself it seems
-- if ( *(_DWORD *)(v18 + 232) & 0x800000 && (v25 = *(_DWORD *)(v9 + 164), v25 == v30) && *(_DWORD *)v9 == 8 )
-- we dont skip the v25 assignment however
function bp_workaround_tdls_state_checks()
    lua_set_pc(0x001CF3AA)
    lua_continue()
end

function bp_fix_tdls_tlvbuf_len()
    lua_set_register(3, 183) -- the length is wrong here, unclear why
    lua_continue()
end

-- see comments below explaining this
function bp_fix_RSN_ie_len_in_mem()
    print("RSN IE len hexdump...")
    hex_dump(lua_read_mem(RSN_ie_len_ptr, 0x10), 0)
    lua_write_byte(RSN_ie_len_ptr, 0x14) -- original length from sample pcap
    hex_dump(lua_read_mem(RSN_ie_len_ptr, 0x10), 0)
    lua_continue()
end

function bp_change_tdls_rsn_ie_len()
    -- If we simply modify r2 here, we won't trigger the overflow, because the value
    -- is again fetched at 0007A8CA from the ie ptr. This became clear after tracing the memcpy offsets
    -- as well. Instead, the below code modifies the memory structure directly. There is one issue with this,
    -- namely that the copied bytes are used as an offset again to determine the interval and FT IE location.
    -- If we do that, we also influence how bcm_parse_tlvs() works though as it keeps iterating over TLVs by
    -- adding the length of the previous IE to find the next one. That means we need to craft the interval and FT
    -- IEs in the TLV buffer again at the right offsets and also adjust the tlv buffer length again as now
    -- bcm_parse_tlvs() has to scan much further. Instead of doing that, we make sure that after the memcpy
    -- of the RSN IE happened, we write back the original length in the TLV buffer. This way we also don't corrupt
    -- the src heap chunk.
    RSN_ie_len_ptr = lua_get_register(0) + 1 -- start of TLV + 1 = len
    lua_write_byte(RSN_ie_len_ptr, 0xff-0x23)
    hex_dump(lua_read_mem(RSN_ie_len_ptr, 0x10), 0)

    lua_breakpoint_insert(0x0007A8D0, bp_fix_RSN_ie_len_in_mem) -- location after memcpy and next bcm_parse_tlvs
    -- if we however modify the structure in memory, we also need to fix the subsequent data
    -- because the length that was copied determines the next offset where the interval IE is expected
    print("heap memory corruption shall commence")
    --lua_continue()
end

function bp_dump_mpu()
    -- http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0363e/Biiijafh.html
    local mpu_size_map = { [19] = '1 MB', [20] = '2 MB', [21] = '4 MB', [22] = '8 MB', [23] = '16 MB', [24] = '32 MB', [25] = '64 MB', [26] = '128 MB', [27] = '256 MB', [28] = '512 MB', [29] = '1 GB', [30] = '2 GB', [31] = '4 GB' }
    local mpu_access_map = { [0] = 'priv: no access; user: no access', [1] = 'priv: read/write; user: no access', [2] = 'priv: read/write; user: read-only', [3] = 'priv: read/write; user: read/write', [4] = 'reserved', [5] = 'priv: read only; user: no access', [6] = 'priv/user: read-only' }
    local bit = require("bit")
    local r0 = lua_get_register(0) -- Write MPU Memory Region Number Register
    local r1 = lua_get_register(1) -- Write Data MPU Region Size and Enable Register
    local r2 = lua_get_register(2) -- Write MPU Region Base Address Register
    local r3 = lua_get_register(3) -- Write Region access control Register

    local size_idx   = bit.band(bit.arshift(tonumber(r1), 1), 0x1f)
    local access_idx = bit.band(bit.arshift(tonumber(r3), 8), 0x7)
    local xn         = bit.band(bit.arshift(tonumber(r3), 12), 0x1)

    local region_size = mpu_size_map[size_idx]
    local access_bits = mpu_access_map[access_idx]


    C.printf("Region %d: 0x%x (%s; size: %s; XN: %d)\n", r0, r2, access_bits, region_size, xn)
    lua_continue()
end

function bp_memcpy()
    C.printf("memcpy(0x%x, 0x%x, %d)\n", lua_get_register(0), lua_get_register(1), lua_get_register(2));
    lua_continue()
end

breakpoints = {
    -- logging
    [0x00003B94] = bp_log_formatted,
    -- breakpoints after having reached end of init
    [0x0018A9F0] = bp_pkt_free,
    [0x00006984] = bp_wfi_loop,
    -- early init fixes
    [0x00181B96] = bp_mod_v15,
    [0x00181BB4] = bp_mod_fff0,
    [0x00181BDA] = bp_fix_core_settings,
    -- middle boot fixes
    [0x00181D70] = bp_skip_btcm_something,
    [0x00188CF2] = bp_soc_sanity_checks_something,
    [0x00014CEA] = bp_si_findcoreidx,
    [0x001DC73C] = bp_skip_init_excp_handler,
    [0x001DC4C0] = bp_module_register_something,
    [0x0019ADD6] = bp_fix_tome_ctl,
    [0x00021818] = bp_wlc_recvfilter,
    [0x0019B2B2] = bp_fix_aosscresp_client_pre_checks,
    [0x0003E2AA] = bp_fix_assocresp_state,
    [0x0019b212] = bp_fix_auth_bsscfg_check,
    [0x0003E938] = bp_fix_authresp_client_pre_checks,

    -- data
    [0x00198728] = bp_fix_tome_data,
    [0x001986FC] = bp_fix_bsscfg_data,
    [0x00197E92] = bp_workaround_v25_pktfree_data,

    -- tdls specific
    [0x0007fb20] = bp_fix_tdls_ext_cap,
    [0x001cf35c] = bp_workaround_peer_connection_check_tdls,
    [0x001CF322] = bp_fix_peer_connection_tdls,
    [0x0007E7B4] = bp_fix_linkid_check_tdls,
    [0x001CF48C] = bp_fix_bcmp_tdls,
    [0x001CF476] = bp_fix_bsccfg_tdls_something,
    [0x001CF390] = bp_workaround_tdls_state_checks,
    -- [0x001CF498] = lua_bp, -- we need to fix the length here. unclear how it was computed wrong

    -- p0 tdls bug
    [0x001CF49A] = bp_fix_tdls_tlvbuf_len, -- before wlc_tdls_cal_mic_chk is called
    [0x0007A8A2] = bp_change_tdls_rsn_ie_len,
    [0x000035F8] = bp_memcpy,
    --[0x00181d0a] = lua_bp,

    -- dump MPU
    [0x00181CDC] = bp_dump_mpu,
}

-------- heap experiments
heap_entries = {}   -- allocated chunks
bounds_entries = {} -- allocated chunks for access that OOB
function malloc_entry_hook()
    alloc_size = lua_get_register(0)
    lua_continue()
end

function malloc_exit_hook()
    alloc_ptr = tonumber(lua_get_register(0))

    if alloc_ptr == 0 then
        C.printf("malloc returned 0 at 0x%x\n", lua_get_pc());
        lua_continue()
        return
    end
    C.printf("0x%x = malloc(%lld)\n", lua_get_register(0), alloc_size);

    --lua_trapped_physregion_add(alloc_ptr, alloc_size, heap_read, heap_write)
    lua_watchpoint_insert(alloc_ptr, alloc_size, WP_MEM_ACCESS, heap_access)
    local oob_ptr = tonumber(alloc_ptr + alloc_size)
    lua_watchpoint_insert(oob_ptr, 4, WP_MEM_ACCESS, bounds_access)
    bounds_entries[oob_ptr] = alloc_ptr
    heap_entries[alloc_ptr] = alloc_size
    -- the bounds entry is needed so we can remove the watchpoint on a free

    lua_continue()
end

function free_entry_hook()
    free_ptr = tonumber(lua_get_register(0))
    C.printf("free(%x)\n", free_ptr)

    --lua_trapped_physregion_remove(free_ptr, heap_entries[free_ptr])
    if heap_entries[free_ptr] ~= nil then
        lua_watchpoint_remove(free_ptr, heap_entries[free_ptr], WP_MEM_ACCESS)
        lua_watchpoint_remove(free_ptr + heap_entries[free_ptr], 4, WP_MEM_ACCESS)
        table.remove(bounds_entries, free_ptr + heap_entries[free_ptr]) -- remove oob ptr
        table.remove(heap_entries, free_ptr)
    else
        C.printf("%x freed, but we have not seen alloc\n", free_ptr)
    end
    lua_continue()
end

function bounds_access(args)
    local pc = lua_get_pc()
    local free_start = 0x0018203C
    local free_end = 0x001820A2
    local malloc_start = 0x00181F28
    local malloc_end = 0x182024
    if free_start < pc and free_end > pc then
        lua_continue()
        return
    end
    if malloc_start < pc and malloc_end > pc then
        lua_continue()
        return
    end

    C.printf("linear out of bounds heap access@0x%08llx accessing 0x%08llx (%lld) (%lld)\n", lua_get_pc(), args.addr, args.len, args.flags)

    local aptr = bounds_entries[tonumber(args.addr)]
    local asize = heap_entries[aptr]
    local cdata_aptr = ffi.new('uint32_t', aptr)
    C.printf("destination buffer: 0x%08llx[0x%08llx] (0x%08llx-0x%08llx)!\n", cdata_aptr, asize, cdata_aptr, cdata_aptr + asize - 4);

    --lua_continue()
end

function heap_access(args)
    local flags = tonumber(args.flags)
    local access_type = lua_wp_flags_str(flags)

    C.printf("heap access@0x%08llx accessing 0x%08llx (%lld) (%lld) < %s\n", lua_get_pc(), args.addr, args.len, args.flags, access_type)
    lua_continue()
end

function heap_read(args)
   C.printf("WR read: 0x%08llx (%lld)\n", args.addr, args.size)
   C.printf("PC = 0x%08llx\n", lua_get_pc())
end

function heap_write(args)
   C.printf("WR write: %08llx (%lld)\n", args.addr, args.size)
   C.printf("PC = 0x%08llx\n", lua_get_pc())
end

function add_malloc_breakpoints()
    --            malloc_1 for now, everything else is a wrapper
    entry_eas = { 0x00181F28 }
    for k,v in pairs(entry_eas) do
        lua_breakpoint_insert(v, malloc_entry_hook)
    end
    exit_eas = { 0x182024 }
    for k,v in pairs(exit_eas) do
        lua_breakpoint_insert(v, malloc_exit_hook)
    end
    --            free
    entry_eas = { 0x0018203C }
    for k,v in pairs(entry_eas) do
        lua_breakpoint_insert(v, free_entry_hook)
    end
end
-------- heap experiments

function post_init()
  --lua_watchregion_add(0x18000000, 8, wr_read_fun, wr_write_fun);
  --add_malloc_breakpoints()
end
