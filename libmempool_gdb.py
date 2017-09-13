#!/usr/bin/python3
#
# This file is part of libmempool.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

################################################################################
# GDB COMMANDS
################################################################################

import gdb
import os
from os.path import basename
from functools import wraps

import traceback
import sys
sys.path.insert(0, os.path.join(os.getcwd(), "libmempool"))
import importlib
import libmempool as lmp
importlib.reload(lmp)

################################################################################
# HELPERS
################################################################################

# Taken from gef. Let's us see proper backtraces from python exceptions
def show_last_exception():
    PYTHON_MAJOR = sys.version_info[0]
    horizontal_line = "-"
    right_arrow = "->"
    down_arrow = "\\->"

    print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(" Exception raised ".center(80, horizontal_line))
    print("{}: {}".format(exc_type.__name__, exc_value))
    print(" Detailed stacktrace ".center(80, horizontal_line))
    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        if PYTHON_MAJOR==2:
            filename, lineno, method, code = fs
        else:
            try:
                filename, lineno, method, code = fs.filename, fs.lineno, fs.name, fs.line
            except:
                filename, lineno, method, code = fs

        print("""{} File "{}", line {:d}, in {}()""".format(down_arrow, filename,
                                                            lineno, method))
        print("   {}    {}".format(right_arrow, code))

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print("[libmempool] No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print("[libmempool] This gdb's python support is too old.")
        exit()

def has_inferior(f):
    "decorator to make sure we have an inferior to operate on"

    @wraps(f)
    def with_inferior(*args, **kwargs):
        inferior = get_inferior()
        if inferior != -1 and inferior != None:
            if (inferior.pid != 0) and (inferior.pid is not None):
                return f(*args, **kwargs)
            else:
                print("[libmempool] No debugee could be found.  Attach or start a program.")
                exit()
        else:
            exit()
    return with_inferior

# This is a super class with few convenience methods to let all the cmds parse
# gdb variables easily
class mpcmd(gdb.Command):
    def __init__(self, name, mh_version=None):
        self.p_char = gdb.lookup_type('char').pointer()
        self.p_long = gdb.lookup_type('long').pointer()
        self.is_x86 = self.p_long.sizeof == 4
        self.mh_version = mh_version
        super(mpcmd, self).__init__(name, gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[libmempool] " + s, end=end)
            else:
                print("[libmempool] " + s)
        else:
            print(s)

    def parse_var(self, var):
        if self.SIZE_SZ == 4:
            p = self.tohex(long(gdb.parse_and_eval(var)), 32)
        elif self.SIZE_SZ == 8:
            p = self.tohex(long(gdb.parse_and_eval(var)), 64)
        return int(p, 16)

    # Because python is incapable of turning a negative integer into a hex
    # value easily apparently...
    def tohex(self, val, nbits):
        result = hex((val + (1 << nbits)) % (1 << nbits))
        # -1 because hex() sometimes(?) tacks on an L to hex values...
        if result[-1] == 'L':
            return result[:-1]
        else:
            return result

    def _get_cpu_register(self, reg):
        """
        Get the value holded by a CPU register
        """

        expr = ''
        if reg[0] == '$':
            expr = reg
        else:
            expr = '$' + reg

        try:
            val = self._normalize_long(long(gdb.parse_and_eval(expr)))
        except:
            self.logmsg("Hum, have you ran the process ? I can't retrieve any register.")
            return None
        return val

    def _normalize_long(self, l):
        return (0xffffffff if self.is_x86 else 0xffffffffffffffff) & l

    def _is_register(self, s):
        """
        bin_size Is it a valid register ?
        """
        x86_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip']
        x64_reg = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'rip'] + ['r%d' % i for i in range(8, 16)]

        if s[0] == '$':
            s = s[1:]

        if s in (x86_reg if self.is_x86 else x64_reg):
            return True
        return False

    def _parse_base_offset(self, r):
        base = r
        offset = 0
        if "+" in r:
            # we assume it is a register or address + a hex value
            tmp = r.split("+")
            base = tmp[0]
            offset = int(tmp[1], 16)
        if "-" in r:
            # we assume it is a register or address - a hex value
            tmp = r.split("-")
            base = tmp[0]
            offset = int(tmp[1], 16)*-1
        if self._is_register(base):
            base = self._get_cpu_register(base)
            if not base:
                return None
        else:
            try:
                # we assume it's an address
                base = int(base, 16)
            except:
                self.logmsg('Error: not an address')
                return None
        return base, offset

    def ptr_from_mh(self, p):
        return (p.address + (p.mp_hdr_sz))

    def print_hexdump(self, p, maxlen=0, off=0):
        data = self.ptr_from_mh(p) + off
        size = p.mh_len - off
        if size <= 0:
            print("[!] Chunk corrupt? Bad size")
            return
        if maxlen != 0:
            if size > maxlen:
                size = maxlen
        print("0x%x bytes of chunk data:" % size)
        if p.SIZE_SZ == 4:
            if size < 4:
                cmd = "x/%dbx 0x%x" % (size, data)
            else:
                cmd = "x/%dwx 0x%x\n" % (size/4, data)
        elif p.SIZE_SZ == 8:
            if size < 4:
                cmd = "x/%dbx 0x%x" % (size, data)
            else:
                cmd = "x/%dwx 0x%x\n" % (size/4, data)
            #cmd = "x/%dgx 0x%x\n" % (size/8, data)
            #cmd = "dps 0x%x %d\n" % (data, size/8)
        gdb.execute(cmd, True)
        return


################################################################################
class mpbin(mpcmd):
    """Walk backwards the asa bin list of current lmp.mp_header to see what bin
    entry it corresponds to. Although this could theoretically be infered from
    the size, the point in part is to find the mstate address if you haven't
    found it yet."""

    def __init__(self, mh_version=None):
        super(mpbin, self).__init__("mpbin", mh_version=mh_version)

    def help(self):
        self.logmsg("usage: mpbin <addr>")
        self.logmsg(" <addr> an mp chunk header")

    @has_inferior
    def invoke(self, arg, from_tty):
        try:
            if arg == '':
                self.help()
                return
            res = None
            for item in arg.split():
                if item.startswith("0x") or item.startswith("$"):
                    res = self._parse_base_offset(item)
                if item.find("-h") != -1:
                    self.help()
                    return
            if res == None:
                self.logmsg('No valid address or register (+ optional offset) supplied"')
                self.help()
                return
            p = res[0] + res[1]
            orig_m = m = lmp.mp_header(addr=p, inuse=True, binelement=True, allocator="dlmalloc", mh_version=self.mh_version)
            if not m.initOK:
                self.logmsg("Invalid lmp.mp_header at 0x%x" % p)
                return
            while True:
                if m.mh_bk_link == 0:
                    bin_i_addr = m.address
                    self.logmsg("Found bin start at 0x%x" % bin_i_addr)
                    bin_i = lmp.mp_header(addr=bin_i_addr, inuse=True, binelement=True, allocator="dlmalloc", mh_version=self.mh_version)
                    # Just get an object reference. Won't be initialized
                    mstate = lmp.mp_mstate(addr=None)
                    mstate_addr = mstate.compute_base_addr(bin_i_addr, orig_m.mh_len)
                    if lmp.mp_mstate_cached == None or \
                            lmp.mp_mstate_cached.address != mstate_addr:
                        lmp.mp_mstate(addr=mstate_addr)
                        self.logmsg("Cached new mp_mstate @ 0x%x" % mstate_addr)
                    break
                p = m.mh_bk_link
                if p != None:
                    m = lmp.mp_header(addr=p, inuse=True, binelement=True, allocator="dlmalloc", mh_version=self.mh_version)
                    if not m.initOK:
                        self.logmsg("Invalid lmp.mp_header at 0x%x" % p)
                        return
                else:
                    self.logmsg("ERROR: Chunk has no mh_bk_link")
                    return

            if lmp.mp_mstate_cached == None:
                self.logmsg("WARN: Can't show mstate entry without cached mstate address")
                self.logmsg("WARN: set with mpmstate <addr> or find with mpbin")
                return
            count = 0
            for b in lmp.mp_mstate_cached.inuse_bins:
                if b == bin_i_addr:
                    break
                count += 1
            string = []
            # calculation for small chunks (<0x1f) is (len >> 3) << 5
            # so (len/8) * 0x20
            if count < 0x20:
                bin_size = count * 8
                string.append("%s%.02d" % ("mp_smallbin[", count))
            # Everything below is derived by compute_tree_index
            # I still can't figure out how to to determine what each index
            # actually is of hand
            else:
                string.append("%s%.02d" % ("mp_treebin[", (count-0x20)))
                # calculation is 0x3f >> (len/256)
                if count == 0x3f:
                    bin_size = 0xffffffff
                else:
                    bin_size = lmp.mp_mstate_cached.treebin_sz[count-0x20]

            string.append("%s%08lx%s%04lx%s%lx" %
                    ("] - sz: 0x",
                        bin_size,
                        " cnt: 0x",
                        lmp.mp_mstate_cached.counters[count],
                        ", mh_fd_link: 0x",
                        bin_i.mh_fd_link))
            if count == 0x3f:
                string.append(" [UNSORTED]")
            self.logmsg(''.join(string))
        except Exception as e:
            show_last_exception()

################################################################################
class mpheader(mpcmd):
    """Meant for analyzing inuse mpheaders. We are unable to infer the layout
     of a free mp_header without knowing the backing allocator, so we don't
     support it. Use libmempool as a callback from libdlmalloc or similar if
     you want to view the free headers."""
    def __init__(self, mh_version=None):
        super(mpheader, self).__init__("mpheader", mh_version=mh_version)

    def help(self):
        self.logmsg('usage: mpheader [-x] <addr>')
        self.logmsg(' <addr> an inuse mp chunk header. must point at mh struct itself')
        self.logmsg(' -x     hexdump the chunk contents')

    @has_inferior
    def invoke(self, arg, from_tty):

        try:
            force = False
            hexdump = False
            res = None
            if arg == '':
                self.help()
                return
            for item in arg.split():
                if item.find("-f") != -1:
                    force = True
                if item.find("-x") != -1:
                    hexdump = True
                if item.startswith("0x") or item.startswith("$"):
                    res = self._parse_base_offset(item)
                if item.find("-h") != -1:
                    self.help()
                    return
            if res == None:
                self.logmsg('No valid address or a register (+ optional offset) supplied"')
                self.help()
                return
            p = res[0] + res[1]
            p = lmp.mp_header(addr=p, allocator="dlmalloc", inuse=True, binelement=True, mh_version=self.mh_version)
            self.logmsg(p)
            if hexdump:
                self.print_hexdump(p)
        except Exception as e:
            show_last_exception()

################################################################################
class mpbinwalk(mpcmd):
    def __init__(self, mh_version=None):
        super(mpbinwalk, self).__init__("mpbinwalk", mh_version=mh_version)

    def help(self):
        self.logmsg('usage: mpbinwalk [-v] [-p <addr>] <sz>')
        self.logmsg(' -p <addr>       address of the mp_mstate')
        self.logmsg(' -P <addr>       address of a lmp.mp_header to start walking instead of using the bin head')
        self.logmsg(' -s <0x01234567> search for 4-byte value in chunk')
        self.logmsg(' --depth <num>   how deep to search inside the chunk')
        self.logmsg(' -o <offset>     search for -s pattern at offset')
        self.logmsg(' -c <num>        number of entries to show')
        self.logmsg(' -v              use verbose output for each chunk')
        self.logmsg(' -l              list every result match/nomatch from -s')
        self.logmsg(' <sz>            size of chunk you want to dump the list for')

    @has_inferior
    def invoke(self, arg, from_tty):
        try:
            verbose = 0
            size = 0
            p = None
            mstate_addr = None
            mh_addr = None
            search_val = None
            search_offset = 0
            search_depth = 0
            count = 0
            P_found = p_found = s_found = o_found = c_found = depth_found = False
            list_all_chunks = False
            if arg == '':
                self.help()
                return
            for item in arg.split():
                if P_found:
                    P_found = False
                    if item.find("0x") != -1:
                        mh_addr = int(item, 16)
                    else:
                        mh_addr = int(item)
                elif p_found:
                    p_found = False
                    if item.find("0x") != -1:
                        mstate_addr = int(item, 16)
                    else:
                        mstate_addr = int(item)
                elif o_found:
                    o_found = False
                    if item.find("0x") != -1:
                        search_offset = int(item, 16)
                    else:
                        search_offset = int(item)
                elif s_found:
                    s_found = False
                    if item.find("0x") != -1:
                        search_val = item
                elif c_found:
                    c_found = False
                    if item.find("0x") != -1:
                        count = int(item, 16)
                    else:
                        count = int(item)
                elif depth_found:
                    depth_found = False
                    if item.find("0x") != -1:
                        search_depth = item
                    else:
                        search_depth = int(item)
                elif item.find("-v") != -1:
                    verbose += 1
                elif item.find("-p") != -1:
                    p_found = True
                elif item.find("-P") != -1:
                    P_found = True
                elif item.find("-l") != -1:
                    list_all_chunks = True
                elif item.find("-s") != -1:
                    s_found = True
                elif item.find("-c") != -1:
                    c_found = True
                elif item.find("--depth") != -1:
                    depth_found = True
                elif item.find("-o") != -1:
                    o_found = True
                elif item.find("0x") != -1:
                    size = int(item, 16)
                elif item.find("-h") != -1:
                    self.help()
                    return

            if mh_addr != None:
                head = lmp.mp_header(addr=mh_addr, binelement=True, mh_version=self.mh_version)
            else:
                if size == 0:
                    self.logmsg("ERROR: No size supplied?")
                    self.help()
                    return

                if mstate_addr == None and lmp.mp_mstate_cached == None:
                    self.logmsg("WARN: Can't show mstate entry without specified "
                           "(-p) or cached mstate address")
                    self.logmsg("WARN: set with mpmstate <addr> or find with mpbin")
                    self.help()
                    return

                if mstate_addr != None:
                    if lmp.mp_mstate_cached != None and \
                            lmp.mp_mstate_cached.address == mstate_addr:
                        mstate = lmp.mp_mstate_cached
                    else:
                        mstate = mp_mstate(mstate_addr)
                        if not mstate.initOK:
                            self.logmsg("ERROR: supplied a bad mstate address?")
                            self.help()
                            return
                    lmp.mp_mstate_cached = mstate
                else:
                    mstate = lmp.mp_mstate_cached

                head = mstate.bin_for_sz(size)

            if verbose:
                self.logmsg(head)
            else:
                if head.mh_len != 0:
                    if search_val == None:
                        self.logmsg(head.info())
                else:
                    self.logmsg(head.info() + " [BIN HEAD]")
            cur = head
            if count == 0:
                count = 0x7fffffff

            if cur.mh_fd_link == 0:
                self.logmsg("<<< EMPTY >>>")
                self.logmsg("Update mstate cache if you think this is wrong")

            show_head = False
            if cur.mh_len != 0:
                show_head = True
            while cur.mh_fd_link != 0 and count != 0:
                count -= 1
                suffix = ""
                if not show_head:
                    cur = lmp.mp_header(addr=cur.mh_fd_link, binelement=True, mh_version=self.mh_version)
                else:
                    show_head = False
                if search_val != None:
                    # Don't print if the chunk doesn't have the pattern
                    if not cur.search_chunk(cur, search_val, depth=search_depth):
                        if not list_all_chunks:
                            continue
                        else:
                            suffix = " [NO MATCH]"
                    else:
                        if list_all_chunks:
                            suffix = " [MATCH]"
                if verbose:
                    self.logmsg(cur)
                else:
                    self.logmsg(cur.info() + suffix)
        except Exception as e:
            show_last_exception()

################################################################################
class mpmstate(mpcmd):
    """Set, cache, and display the mempool portion of an mstate structure"""

    def __init__(self, mh_version=None):
        super(mpmstate, self).__init__("mpmstate", mh_version=mh_version)

    def help(self):
        self.logmsg("usage: mpmstate <addr>")
        self.logmsg(" <addr> an mp_mstate structure address")

    @has_inferior
    def invoke(self, arg, from_tty):
        try:
            if arg == '':
                self.help()
                return
            res = None
            for item in arg.split():
                if item.startswith("0x") or item.startswith("$"):
                    res = self._parse_base_offset(item)
                if item.find("-h") != -1:
                    self.help()
                    return
            if res == None:
                self.logmsg('No valid address or register (+ optional offset) supplied"')
                self.help()
                return
            p = res[0] + res[1]
            mstate = lmp.mp_mstate(addr=p)
            print(mstate)
        except Exception as e:
            show_last_exception()

###############################################################################
class mphelp(mpcmd):
    "Details about all libmempool gdb commands"

    def __init__(self, mh_version=None, help_extra=None):
        self.help_extra = help_extra
        super(mphelp, self).__init__("mphelp", mh_version=mh_version)

    def invoke(self, arg, from_tty):
        self.logmsg('mempool commands for gdb')
        if self.help_extra != None:
            self.logmsg(self.help_extra)
        self.logmsg('mpheader -v -x <addr>           : show chunk contents (-v for verbose, -x for data dump)')
        self.logmsg("mpbinwalk [-v] [-p <addr>] <sz> : walk an mpbin and operate on each chunk in a bin")
        self.logmsg('mpbin <addr>                    : determine to which bin an mp_header is associated to')
        self.logmsg('mpmstate <addr>                 : display and cache a mempool mstate address')
        self.logmsg('mphelp                          : this help message')

if __name__ == "__main__":
    mphelp()
    mpbinwalk()
    mpheader()
    mpbin()
    mpmstate()

    mpcmd.logmsg("loaded")
