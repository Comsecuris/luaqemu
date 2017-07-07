-- Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)
-- this file provides very basic pthread support for LuaQEMU
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

local ffi = require('ffi')
local C = ffi.C
local pt = ffi.load('pthread')

-- see pthreadtypes.h
if ffi.arch == "x64" then
    ffi.cdef[[
        static const int __SIZEOF_PTHREAD_ATTR_T = 56;
    ]]
elseif ffi.arch == "x86" then
    ffi.cdef[[
        static const int __SIZEOF_PTHREAD_ATTR_T = 32;
    ]]
else
    ffi.cdef[[
        static const int __SIZEOF_PTHREAD_ATTR_T = 36;
    ]]
end

-- pthreadtypes.h and pthread.h
ffi.cdef[[
/* Thread identifiers.  The structure of the attribute type is not
   exposed on purpose.  */
typedef unsigned long int pthread_t;

typedef union
{
  char __size[__SIZEOF_PTHREAD_ATTR_T];
  long int __align;
} pthread_attr_t;

extern int pthread_create (pthread_t *__newthread,
                           const pthread_attr_t * __attr,
                           void *(*__start_routine) (void *),
                           void * __arg);

void pthread_exit (void *__retval);
int pthread_join (pthread_t __th, void **__thread_return);

typedef void *(*start_routine)(void *);
]]

-- lua.h/lauxlib.h/lualib.h
ffi.cdef[[
typedef struct lua_State lua_State;
static const int LUA_GLOBALSINDEX = -10002;

lua_State *luaL_newstate (void);
void lua_close (lua_State *L);
/*lua_State *lua_newthread (lua_State *L);*/
void luaL_openlibs (lua_State *L);
int luaL_loadstring (lua_State *L, const char *s);
int lua_pcall (lua_State *L, int nargs, int nresults, int errfunc);
void lua_getfield (lua_State *L, int idx, const char *k);
ptrdiff_t lua_tointeger (lua_State *L, int idx);
void lua_settop (lua_State *L, int idx);
]]

pthread = {}
pthread.threads = {}
pthread.pt = pt

--extern int pthread_create (pthread_t *__newthread,
--                           const pthread_attr_t * __attr,
--                           void *(*__start_routine) (void *),
--                           void * __arg);
function pthread.pthread_create(attr, func, arg)
    -- create new lua context
    local L = C.luaL_newstate()
    C.luaL_openlibs(L)
    print(debug.getupvalue, func, nil)

    C.luaL_loadstring(L, [[
        -- upvalues are not copied, we need to require ffi again
        local ffi = require('ffi')
        local function func()
            local i = 0
            while true do
                print("thread foobar")
                i = i + 1
            end
        end
        lua_pt_callback = tonumber(ffi.cast('intptr_t', ffi.cast('void *(*)(void *)', func)))
    ]])

    C.lua_pcall(L, 0, 1, 0)
    C.lua_getfield(L, C.LUA_GLOBALSINDEX, 'lua_pt_callback')
    local fn = C.lua_tointeger(L, -1)
    C.lua_settop(L, -2); -- clear stack

    local thread_id = ffi.new('pthread_t[1]')
    local ret = pthread.pt.pthread_create(thread_id, attr, ffi.cast('start_routine', fn), nil)

    pthread.threads[thread_id] = L
    return ret, thread_id
end

function pthread.pthread_join(thread, retval)
    local ret = pthread.pt.pthread_join(thread[0], nil)
    C.lua_close(pthread.threads[thread])
    return ret
end
