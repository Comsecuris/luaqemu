-- Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)
-- completely untested
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

local ffi = require "ffi"

ffi.cdef[[
    static const int SOCK_STREAM = 1;

    static const int PF_INET = 2;
    static const int AF_INET = PF_INET;

    typedef unsigned short int sa_family_t;
    typedef uint32_t in_addr_t;

    /* Structure describing a generic socket address.  */
    struct sockaddr
      {
        sa_family_t sin_family;
        char sa_data[14];           /* Address data.  */
      };

    typedef uint32_t socklen_t;
    typedef int ssize_t;

    struct sockaddr_in {
        sa_family_t sin_family;
        uint16_t sin_port;
        struct in_addr sin_addr;
        /* Pad to size of `struct sockaddr'. */
        unsigned char __pad[sizeof(struct sockaddr) - sizeof(sa_family_t) - sizeof(uint16_t) - sizeof(struct in_addr)];
    };

    int socket(int domain, int type, int protocol);
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int listen(int sockfd, int backlog)
    int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

    uint16_t htons(uint16_t hostshort);
    int inet_aton(const char *cp, struct in_addr *inp);

    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
    int close(int fd);
]]
