#!/usr/bin/python3
#
# This file is part of libmempool.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

from __future__ import print_function
import re, os
import sys
import struct
import traceback
import pickle
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

VERBOSE = 0

HOST = "localhost"
PORT = 9100

RETSYNC_NONE = 0
RETSYNC_GDB_COMMAND = 1
RETSYNC_JSON_PROTO = 2
global ret_sync
ret_sync = RETSYNC_NONE
global rln
rln = None
# We only use a symbols cache for RETSYNC_JSON_PROTO as it is meant to be
# used offline where things do not change over time
global symbols_cache
symbols_cache = {}
global symbols_cache_file
symbols_cache_file = None

def logmsg(s, end=None):
    if type(s) == str:
        if end != None:
            print("[libmempool] " + s, end=end)
        else:
            print("[libmempool] " + s)
    else:
        print(s)

myself_path = sys.path[0]
try:
    import gdb
except ImportError:
    logmsg("WARNING: No gdb environment found. Limited functionality available")
    try:
        sys.path.insert(0, os.path.join(myself_path, ".."))
        import asa_sync
    except ImportError:
        logmsg("WARNING: No asa_sync available. Limited functionality available")
    else:
        try:
            sys.path.insert(0, os.path.join(myself_path, "..", "ret-sync", "ext_python"))
            import sync
        except ImportError:
            logmsg("WARNING: No ret-sync Python API available. Limited functionality available")
        else:
            logmsg("Using ret-sync over JSON")
            ret_sync = RETSYNC_JSON_PROTO
else:
    ret_sync = RETSYNC_GDB_COMMAND
    logmsg("Using ret-sync over GDB commands")
    
global mp_mstate_cached
mp_mstate_cached = None

def init_sync(bin_name):
    global ret_sync, rln
    global HOST, PORT

    if ret_sync != RETSYNC_JSON_PROTO:
        logmsg("WARNING: ret-sync with json disabled")
        return

    locations = [os.path.join(os.path.realpath(os.path.dirname(__file__)), ".sync"),
                 os.path.join(os.environ['HOME'], ".sync")]

    for confpath in locations:
        if os.path.exists(confpath):
            config = configparser.SafeConfigParser({'host': HOST, 'port': PORT})
            config.read(confpath)
            HOST = config.get("INTERFACE", 'host')
            PORT = config.getint("INTERFACE", 'port')
            print("[sync] configuration file loaded %s:%s" % (HOST, PORT))
            break

    ##### Cisco ASA specific
    logmsg("firmware name: %s" % bin_name)

    try:
        mappings = asa_sync.global_mappings[bin_name]
        mappings = asa_sync.patch_mapping(mappings, bin_name)
    except KeyError:
        logmsg("ERROR: no mapping defined for %s" % bin_name)
        return
    logmsg("mappings: %s" % (mappings))

    s = sync.Sync(HOST, maps=mappings)
    # add a bit more so we are in the .text section :)
    s.invoke(offset=mappings[0][0]+0x8000)
    rln = sync.Rln(s)
    ##### end of Cisco ASA specific

    global symbols_cache, symbols_cache_file
    symbols_cache_file = bin_name + ".symcached"
    if os.path.isfile(symbols_cache_file):
        logmsg("Loading cached symbols from %s" % symbols_cache_file)
        symbols_cache = pickle.load(open(symbols_cache_file, "rb"))
# We have encountered two versions so far for the mempool header
MEMPOOL_VERSION_1 = 1   # e.g. used in asa803-k8.bin
MEMPOOL_VERSION_2 = 2   # most used
# hax so we can switch manually here to another version to be used by the callback
# XXX - We want to automatically detect the heap allocator hence the mempool header version used
current_mempool_version = MEMPOOL_VERSION_2

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




# XXX - Would prefer to not have any gdb-specific code in here
def get_inferior():
    try:
        import gdb
        if len(gdb.inferiors()) == 0:
            print("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print("This gdb's python support is too old.")
        exit()
    except NameError:
        return None


################################################################################
# CALLBACKS
################################################################################

# Main callback to be registered in libptmalloc and libdlmalloc
def mpcallback(cbinfo):
    # sanity checks
    if "caller" not in cbinfo:
        print("[libmempool] Missing caller")
        return 0
    if "allocator" not in cbinfo:
        print("[libmempool] Missing allocator")
        return 0
    if cbinfo["allocator"] != "dlmalloc" and cbinfo["allocator"] != "ptmalloc":
        print("[libmempool] Allocator not supported")
        return 0
    if "addr" not in cbinfo:
        print("[libmempool] Missing addr")
        return 0

    if cbinfo["caller"] == "dlmstate":
        return parse_mstate(cbinfo)
    elif cbinfo["caller"] == "dlchunk" or cbinfo["caller"] == "ptchunk" \
         or cbinfo["caller"] == "ptchunk_info":
        return parse_chunk(cbinfo)
    elif cbinfo["caller"] == "check_inuse":
        return chunk_has_inuse_magic(cbinfo)
    else:
        print("[libmempool] Unknown caller")
        return None

def chunk_has_inuse_magic(cbinfo):
    inferior = get_inferior()
    mem = inferior.read_memory(cbinfo["addr"]+cbinfo["hdr_sz"], 4)
    next_word = struct.unpack_from("<I", mem, 0x0)[0]
    if next_word != 0xa11c0123:
        return False
    return True

def parse_mstate(cbinfo):
    global mp_mstate_cached
    if cbinfo["allocator"] != "dlmalloc":
        print("[libmempool] Only dlmalloc support for mstate for now")
        return 0

    if cbinfo["addr"] != None:
        addr = cbinfo["addr"]
        if mp_mstate_cached != None and addr == mp_mstate_cached.address:
            mp = mp_mstate_cached
        else:
            mp = mp_mstate(size_sz=cbinfo["size_sz"], addr=addr)
            mp_mstate_cached = mp
        if mp != None:
            print(mp)
    else:
        print("[libmempool] Bad address supplied to callback")
        return 0x0

# Can return either an two different types depending on what the requestor
# wants:
#   - integer: the size of the mp_header
#   - string : some extra info for printing out chunk data
#
# In the case it returns an integer, it will also typically print verbose
# information about the header
def parse_chunk(cbinfo):
    global current_mempool_version

    if "hdr_sz" not in cbinfo:
        print("[libmempool] Missing hdr_sz")
        return 0
    if "min_hdr_sz" not in cbinfo:
        print("[libmempool] Missing min_hdr_sz")
        return 0
    if "chunksz" not in cbinfo:
        print("[libmempool] Missing chunksz")
        return 0

    # allow to force printing mp_header even though it does not look valid
    debug = False
    if "debug" in cbinfo:
        debug = True

    if cbinfo["allocator"] == "dlmalloc":
        if "version" in cbinfo:
            if cbinfo["version"] == "2.6":
                current_mempool_version = MEMPOOL_VERSION_1
            elif cbinfo["version"] == "2.8":
                current_mempool_version = MEMPOOL_VERSION_2
        # There are a few cases where there will be no room for an mp header
        if (cbinfo["chunksz"]-cbinfo["hdr_sz"]) <= 0:
            if "chunk_info" in cbinfo and cbinfo["chunk_info"] == True:
                return 0
            else:
                # XXX - possibly should be a debug-only statement
                print("[libmempool] in callback, not enough data to fit hdr")
                return 0

#    if "chunksz" in cbinfo:
#        inuse = cbinfo["chunksz"]
#    else:
#        return 0

    if "inuse" in cbinfo:
        inuse = cbinfo["inuse"]
    else:
        print("[libmempool] Missing inuse")
        return 0

    inuse_override = None
    if "inuse_override" in cbinfo:
        inuse_override = cbinfo["inuse_override"]

    # This is currently needed if we want the hdr size and not to print
    if "no_print" in cbinfo:
        no_print = cbinfo["no_print"]
    else:
        no_print = False

    # XXX - This probably isn't the best name?
    if "chunk_info" in cbinfo:
        chunk_info = cbinfo["chunk_info"]
    else:
        chunk_info = False

    if cbinfo["addr"] != None:
        if "mem" in cbinfo:
            mh = mp_header(size_sz=cbinfo["size_sz"], mem=cbinfo["mem"], addr=cbinfo["addr"],
                    allocator=cbinfo["allocator"], hdr_sz=cbinfo["hdr_sz"],
                    min_hdr_sz=cbinfo["min_hdr_sz"], chunksz=cbinfo["chunksz"],
                    inuse=inuse)
        else:
            mh = mp_header(size_sz=cbinfo["size_sz"], addr=cbinfo["addr"], allocator=cbinfo["allocator"],
                    hdr_sz=cbinfo["hdr_sz"], min_hdr_sz=cbinfo["min_hdr_sz"],
                    chunksz=cbinfo["chunksz"], inuse=inuse)
        #print("[libmempool] mp_header size = 0x%x" % mh.mp_hdr_sz)
        if mh.mp_hdr_sz != 0 and chunk_info:
            if inuse_override != None and inuse_override == False:
                inuse = 0

            if inuse == 1:
                return "alloc_pc:{0:#010x},{1:s}".format(mh.alloc_pc,
                        mh.retsync_rln(mh.alloc_pc))
            else:
                if current_mempool_version == MEMPOOL_VERSION_2:
                    return " free_pc:{0:#010x},{1:s}".format(mh.free_pc,
                            mh.retsync_rln(mh.free_pc))
                else:
                    return "alloc_pc(before free):{0:#010x},{1:s}".format(mh.alloc_pc,
                            mh.retsync_rln(mh.alloc_pc))

        if mh.mp_hdr_sz != 0 and not no_print:
            print(mh)
        elif debug:
            if no_print:
                print('[libmempool] Parsed and chose not to print mp header')
            else:
                print(mh)
        return mh.mp_hdr_sz
    else:
        print("[libmempool] Bad address supplied to callback")
        return 0

################################################################################
# STRUCTURES
################################################################################

# similar to *_structure in other files
# XXX - this should possibly move into _gdb.py file
class mp_structure(object):

    def __init__(self):
        self.is_x86 = self.SIZE_SZ == 4
        self.initOK = True

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
        except Exception:
            print("No process running? Can't read registers")
            return None
        return val

    def _normalize_long(self, l):
        return (0xffffffff if self.is_x86 else 0xffffffffffffffff) & l

    def _is_register(self, s):
        """
        bin_size Is it a valid register ?
        """
        x86_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi',
                   'edi', 'esp', 'ebp', 'eip']
        x64_reg = ['rax', 'rbx', 'rcx', 'rdx', 'rsi',
                   'rdi', 'rsp', 'rbp', 'rip'] \
                   + ['r%d' % i for i in range(8, 16)]

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
            except Exception:
                print('Error: not an address')
                return None
        return base, offset

# General class for all helper methods to avoid namespace overlap with other
# heap libraries
class mp_helper(mp_structure):

    def __init__(self, size_sz=0):
        # Cisco ASA mp inuse chunk header
        self.INUSE_MAGIC  = 0xa11c0123
        self.INUSE_FOOTER = 0xa11ccdef
        self.FREE_MAGIC   = 0xf3ee0123
        self.FREE_FOOTER  = 0xf3eecdef
        self.FREE_FOOTER2 = 0x5ee33210

        if size_sz == 0:
            try:
                self.retrieve_sizesz()
            except Exception as e:
                show_last_exception()
                self.SIZE_SZ = 4
        else:
            self.SIZE_SZ = size_sz

        if self.SIZE_SZ == 4:
            self.MH_INUSE_SZ = 0x20
            self.MH_FREE_SZ = 0x18
            self.MH_TINYFREE_SZ = 0x8
        elif self.SIZE_SZ == 8:
            self.MH_INUSE_SZ = 0x30
            self.MH_FREE_SZ = 0x20
            self.MH_TINYFREE_SZ = 0x10 # XXX - check

        super(mp_helper, self).__init__()

    def logmsg(s, end=None):
        if type(s) == str:
            if end != None:
                print("[libmempool] " + s, end=end)
            else:
                print("[libmempool] " + s)
        else:
            print(s)


    def retrieve_sizesz(self):
        """Retrieve the SIZE_SZ after binary loading finished, this allows
           import within .gdbinit"""

        _machine = self.get_arch()

        if "elf64" in _machine:
            self.SIZE_SZ = 8
        elif "elf32" in _machine:
            self.SIZE_SZ = 4
        else:
            raise Exception("Retrieving the SIZE_SZ failed.")

    def get_arch(self):
        res = gdb.execute("maintenance info sections ?", to_string=True)
        if "elf32-i386" in res and "elf64-x86-64" in res:
            raise("get_arch: could not determine arch (1)")
        if "elf32-i386" not in res and "elf64-x86-64" not in res:
            raise("get_arch: could not determine arch (2)")
        if "elf32-i386" in res:
            return "elf32-i386"
        elif "elf64-x86-64" in res:
            return "elf64-x86-64"
        else:
            raise("get_arch: failed to find arch")


    # Depth allows faster searching over serial connections
    def search_chunk(self, p, search_for, depth=0):
        "searches a chunk. includes the chunk header in the search"

        if depth == 0 or depth > p.mh_len:
            depth = p.mh_len

        try:
            cmd = 'find /1w 0x%x, 0x%x, %s' % \
                (p.address, p.address + depth, search_for)
            import gdb
            out_str = gdb.execute(cmd, \
                to_string = True)
        except Exception:
            print(sys.exc_info()[0])
            print("[libmempool] failed to execute 'find'")
            return False

        str_results = out_str.split('\n')

        for str_result in str_results:
            if str_result.startswith('0x'):
                return True

        return False

################################################################################
class mp_mstate(mp_helper):
    """python representation of the cisco portion of an mstate struct after the
       dlmstate.
       NOTE: even on 64-bit where ptmalloc is used, there is a dlmstate holding
       an empty dlmstate and the actual cisco portion that we named 'mp_mstate'
    """
    nbins           = 0x40
    NSMALLBINS      = 0x20
    MAXSMALLBIN     = 0xf8
    NTREEBINS       = 0x20
    nbins           = NSMALLBINS + NTREEBINS
    ncounters       = nbins

    treebin_sz = [ 0x180, 0x200, 0x300, 0x400, 0x600, 0x800, 0xc00, 0x1000,
        0x1800, 0x2000, 0x3000, 0x4000, 0x6000, 0x8000, 0xc000, 0x10000,
        0x18000, 0x20000, 0x30000, 0x40000, 0x60000, 0x80000, 0xc0000, 0x100000,
        0x180000, 0x200000, 0x300000, 0x400000, 0x600000, 0x800000, 0xc00000,
        0xffffffff]

    def __init__(self, size_sz=0, addr=None, mem=None):
        super(mp_mstate, self).__init__(size_sz=size_sz)
        global mp_mstate_cached
        self.MH_MSPACE_SZ = (self.nbins * self.MH_INUSE_SZ) \
                            + (self.nbins * 4)
        self.initOK = True
        self.str_name = "mp_mstate"
        self.inuse_bins = []
        self.counters = None
        self.bins_off = 0
        self.counter_offset = self.bins_off \
                              + (self.nbins * self.MH_INUSE_SZ)
        self.inferior = None

        if addr == None or addr == 0:
            if mem == None:
                self.initOK = False
                return
            self.address = None
        else:
            self.address = addr

        if self.inferior == None and mem == None:
            self.inferior = get_inferior()
            if self.inferior == -1 or self.inferior == None:
                print("[libmempool] Error getting inferior")
                self.initOK = False
                return

        if mem == None:
            # a string of raw memory was not provided
            try:
                mem = self.inferior.read_memory(addr, self.MH_MSPACE_SZ)
            except TypeError:
                print("[libmempool] Invalid address specified.")
                self.initOK = False
                return
            except RuntimeError:
                print("[libmempool] Could not read address {0:#x}".format(addr))
                self.initOK = False
                return

        count = 0
        while count < self.nbins:
            bin_offset = self.bins_off + (count * self.MH_INUSE_SZ)
            # we only store the address of the mp_header() as it is the only
            # one remaining unchanged
            self.inuse_bins.append(self.address + bin_offset)
            count += 1
        self.counters = struct.unpack_from("<%dI" % self.nbins, mem,
                self.counter_offset)

        mp_mstate_cached = self

    def bin_for_sz(self, sz):
        if sz <= self.MAXSMALLBIN:
            idx = self.compute_smallbin_index(sz)

        else:
            # 0x20 is the index that the treebins start
            idx = self.compute_treebin_index(sz) + 0x20

        bin_addr = self.address + (self.MH_INUSE_SZ * idx)
        return mp_header(addr=bin_addr, binhead=True)

    def compute_index(self, sz):
        if sz <= self.MAXSMALLBIN:
            return self.compute_smallbin_index(sz)
        else:
            return self.compute_treebin_index(sz)

    def compute_base_addr(self, bin_addr, mh_len):
        # 4 for footer, self.SIZE_SZ * 2 for in-use chunk header
        real_sz = mh_len + self.MH_INUSE_SZ + 4 + self.SIZE_SZ * 2
        idx = self.compute_index(real_sz)
        if real_sz > self.MAXSMALLBIN:
            idx += 0x20
        bin_offset = idx * self.MH_INUSE_SZ
        self.address = bin_addr - bin_offset
        return self.address

    def compute_smallbin_index(self, sz):
        return int(sz / 8)

    def compute_treebin_index(self, sz):
        count = 0
        for tbsz in self.treebin_sz:
            if sz <= tbsz:
#            if sz <= self.treebin_sz[count]:
                return count
            count += 1

    def __str__(self):
        string = []
        string.append("%s%lx%s" % ("struct " + self.str_name + " @ 0x",
                    self.address, " {\n"))
        count = 0
        # calculation for small chunks (<0x1f) is (len >> 3) << 5
        # so (len/8) * 0x20
        for bin_i_addr in self.inuse_bins:
            # We fake the fact that it is an allocated chunk though there is
            # only a mp_header() here so it successfully creates this object
            INUSE_HDR_SZ = 2 * self.SIZE_SZ
            CHUNK_SZ = INUSE_HDR_SZ + 2 * self.SIZE_SZ
            bin_i = mp_header(addr=bin_i_addr, allocator="dlmalloc", inuse=True,
                    hdr_sz=INUSE_HDR_SZ, chunksz=CHUNK_SZ, binelement=True)
            if bin_i == None or bin_i.mh_fd_link == None:
                print(bin_i.initOK)
                print("[libmempool] [!] Error parsing bin. Something is wrong...")
                return ''
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
                    bin_size = self.treebin_sz[count-0x20]

            string.append("%s%08lx%s%04lx%s%lx" %
                    ("] - sz: 0x",
                        bin_size,
                        " cnt: 0x",
                        self.counters[count],
                        ", mh_fd_link: 0x",
                        bin_i.mh_fd_link))
            if count == 0x3f:
                string.append(" [UNSORTED]")
            string.append("\n")
            count += 1

        return ''.join(string)

################################################################################
class mp_header(mp_helper):
    "py representation of struct mp_header defined in src/checkheaps.h"

    # XXX - A lot of these should be set directly instead of passed as args
    # XXX - Should list which ones are explicitly required
    # addr is the data address for the allocator (ptmalloc/dlmalloc) so it is
    # the start of the mp header
    # size          = unused yet
    # inuse         = we trust the caller if it specifies it
    # allocator     = dlmalloc or ptmalloc
    # hdr_sz        = size of the allocator header
    # min_hdr_sz    = allocator INUSE_HDR_SZ
    # chunksz       = chunk size indicated in the allocator header
    # check         = indicates if we should check mp_header values and display
    #                 more info
    # binhead       = special case for a mempool bin head as most fields are
    #                 NULL except mh_fd_link
    def __init__(self, size_sz=0, addr=None, mem=None, size=None, inuse=None,
            allocator="dlmalloc", hdr_sz=None, min_hdr_sz=None, chunksz=None,
            check=True, binhead=False, binelement=False, mh_version=None):
        super(mp_header, self).__init__(size_sz=size_sz)

        global current_mempool_version

        self.mh_magic         = 0
        self.mh_len           = 0
        self.mh_refcount      = 0
        self.mh_unused        = 0       # v2 only
        self.mh_bk_link       = None
        self.mh_fd_link       = None
        self.alloc_pc         = None
        self.free_pc          = None    # v2 only

        self.mh_unused1          = None # v1 only
        self.mh_unused2          = None # v1 only

        self.str_name         = "mp_header"
        self.tiny_name        = "mp_tiny_free_header"
        self.inferior         = None
        self.address          = None
        self.chunksz          = chunksz
        self.hdr_sz           = hdr_sz
        if mem == None:
            self.check        = check
        else:
            # We don't check if we have mem= because we don't support
            # address lookups inside mem
            self.check        = False

        self.inuse            = None
        if inuse != None:
            self.inuse = inuse
        self.free_struct      = None
        self.fast_free_struct = None
        self.tiny_free_struct = None

        self.mp_hdr_sz        = 0
        self.mh_version       = mh_version

        if self.mh_version == None:
            #print("[libmempool] [!] Version not specified, defaulting to version: %d" % current_mempool_version)
            self.mh_version = current_mempool_version

        # override what should be a binhead/binelement
        if binhead == True:
            inuse = True
            INUSE_HDR_SZ = 2 * self.SIZE_SZ
            hdr_sz = INUSE_HDR_SZ
            binelement = True
        if binelement == True:
            inuse = True
            INUSE_HDR_SZ = 2 * self.SIZE_SZ
            hdr_sz = INUSE_HDR_SZ

        if not binelement:
            # 0x20 chunks cannot contain an mp_header in 64-bit
            if chunksz != None and hdr_sz != None and chunksz <= hdr_sz:
                print("[libmempool] Chunk too small to contain an mp_header")
                self.initOK = False
                return

            if allocator != "dlmalloc" and allocator != "ptmalloc":
                print("[libmempool] Bad allocator")
                self.initOK = False
                return

        # we can use the hdr_sz to determine what kind of chunk if it and how
        # the mp header will look like
        if allocator == "ptmalloc":
            INUSE_HDR_SZ      = 2 * self.SIZE_SZ
            FASTFREE_HDR_SZ   = 3 * self.SIZE_SZ
            FREE_HDR_SZ       = 4 * self.SIZE_SZ
            FREE_LARGE_HDR_SZ = 6 * self.SIZE_SZ
        elif allocator == "dlmalloc":
            INUSE_HDR_SZ      = 2 * self.SIZE_SZ
            FASTFREE_HDR_SZ   = 3 * self.SIZE_SZ # does not exist but we define it so no error below
            FREE_HDR_SZ       = 4 * self.SIZE_SZ
            FREE_LARGE_HDR_SZ = 8 * self.SIZE_SZ # TREE_HDR_SZ
        if hdr_sz != None:
            if hdr_sz == INUSE_HDR_SZ:
                self.inuse = True
            elif hdr_sz == FASTFREE_HDR_SZ:
                self.free_struct = True
            elif hdr_sz == FREE_HDR_SZ:
                self.free_struct = True
            elif hdr_sz == FREE_LARGE_HDR_SZ:
                self.tiny_free_struct = True

        if inuse == True:
            if hdr_sz != INUSE_HDR_SZ:
                print("[libmempool] Warning: caller specified a bad hdr_sz for an inuse chunk")
        elif inuse == False:
            if hdr_sz != FREE_HDR_SZ and hdr_sz != FREE_LARGE_HDR_SZ and hdr_sz != FASTFREE_HDR_SZ:
                print("[libmempool] Warning: caller specified a bad hdr_sz for an free chunk")

        # parse the input address
        # addr is the data address for the allocator (ptmalloc/dlmalloc) so it is the start of the mp header
        if addr == None or addr == 0:
            if mem == None:
                print("[libmempool] Can't parse mstate with no addr or buffer")
                self.initOK = False
                return
            self.address = None
        elif type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                print('The first argument MUST be either an address or a register (+ optional offset)"')
                self.initOK = False
                return
            self.address = res[0] + res[1]
        else:
            self.address = addr

        if self.inferior == None and mem == None:
            self.inferior = get_inferior()
            if self.inferior == -1 or self.inferior == None:
                print("[libmempool] Error getting inferior")
                self.initOK = False
                return

        if mem == None:
            # a string of raw memory was not provided
            try:
                # read the maximum header length possible so we have it for below
                mem = self.inferior.read_memory(self.address, self.MH_INUSE_SZ)
            except TypeError:
                print("Invalid address specified.")
                return None
            except RuntimeError:
                print("Could not read address {0:#x}".format(self.address))
                return None
        else:
            # a string of raw memory was provided
            mlen = len(mem)
            if inuse:
                if (mlen != self.MH_INUSE_SZ) and (mlen < self.MH_INUSE_SZ):
                    print("Insufficient memory (%d bytes) provided for an mp header. Need at least %d bytes" % (mlen, self.MH_INUSE_SZ))
                    return None
            # XXX - This is weird because if we look at the actual address returned
            # by malloc to analyze the mp header then we can rely on
            # MH_INUSE_SZ, but if they specify the _real_ start address
            # of the free mp header, then we have to rely on MH_FREE_SZ
            # Maybe do this a different way
            else:
                if (mlen != self.MH_FREE_SZ) and (mlen < self.MH_FREE_SZ):
                    print("Insufficient memory provided for a free mp header.")
                    return None

        if self.mh_version == MEMPOOL_VERSION_1:
            self.parse_v1(mem)
        else:
            self.parse_v2(mem)

    def parse_v1(self, mem):
        if self.inuse == True:
            self.mp_hdr_sz = self.MH_INUSE_SZ
            if self.SIZE_SZ == 4:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.mh_unused1,
                self.mh_unused2
                ) = struct.unpack_from("<IIIIIIII", mem, 0)
            elif self.SIZE_SZ == 8:
                print("[libmempool] 64-bit not supported yet for v1 as never encountered")
        elif self.free_struct == True:
            self.mp_hdr_sz = self.MH_FREE_SZ
            if self.SIZE_SZ == 4:
                (self.mh_refcount,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.mh_unused1,
                self.mh_unused2
                ) = struct.unpack_from("<IIIIII", mem, 0)
            elif self.SIZE_SZ == 8:
                print("[libmempool] 64-bit not supported yet for v1 as never encountered")
        elif self.tiny_free_struct == True:
            self.mp_hdr_sz = self.MH_TINYFREE_SZ
            if self.SIZE_SZ == 4:
                (self.alloc_pc,
                self.free_pc) = struct.unpack_from("<II", mem, 0)
            elif self.SIZE_SZ == 8:
                print("[libmempool] 64-bit not supported yet for v1 as never encountered")

        else:
            # this is to deal with when the allocator
            # is not aware if the chunk is allocated, etc.
            # or when we instantiate an mp_header without
            # any allocator context
            # So we have to try to guess what is the actual mp_header format
            print("[libmempool] Trying to guess the format of the mp_header")

            if self.SIZE_SZ == 4:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.mh_unused1,
                self.mh_unused2
                ) = struct.unpack_from("<8I", mem, 0)
            elif self.SIZE_SZ == 8:
                print("[libmempool] 64-bit not supported yet for v1 as never encountered")

            # We have to do a special test here to see if we are allocated or free.
            # Also the structure placement when free is dependent on the parent
            # size of the chunk on some heaps. Like > 256 chunk will be a tree
            # chunk on dlmalloc, which has an extra 0x10 bytes of overhead. We try
            # to work out where we are without relying explicitly on the parent
            # heap.
            if self.mh_magic == self.INUSE_MAGIC:
                self.inuse = True
                self.mp_hdr_sz = self.MH_INUSE_SZ
            elif self.mh_refcount == self.FREE_MAGIC:
                self.inuse = False
                self.mp_hdr_sz = self.MH_FREE_SZ
            elif self.alloc_pc == self.FREE_MAGIC:
                self.tiny_free_struct = True
                self.mp_hdr_sz = self.MH_TINYFREE_SZ
            else:
                # we haven't found the magic but we are going to trust the caller that
                # indicated if the chunk is inuse
                if self.inuse != None:
                    if self.inuse == True:
                        self.mp_hdr_sz = self.MH_INUSE_SZ
                    else:
                        # assume a regular free, not tiny?
                        self.mp_hdr_sz = self.MH_FREE_SZ
                else:
                    # if we don't find the magic, we assume this dlmalloc/ptmalloc chunk
                    # has been allocated by a non cisco-wrapped allocation function
                    self.mp_hdr_sz = 0
                    self.initOK = False
                    return

    def parse_v2(self, mem):
        if self.inuse == True:
            self.mp_hdr_sz = self.MH_INUSE_SZ
            if self.SIZE_SZ == 4:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc) = struct.unpack_from("<IIIIIIII", mem, 0)
            elif self.SIZE_SZ == 8:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc) = struct.unpack_from("<IIIIQQQQ", mem, 0)
        elif self.free_struct == True:
            self.mp_hdr_sz = self.MH_FREE_SZ
            if self.SIZE_SZ == 4:
                (self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc) = struct.unpack_from("<IIIIII", mem, 0)
            elif self.SIZE_SZ == 8:
                (self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc) = struct.unpack_from("<IIQQQQ", mem, 0)
        elif self.tiny_free_struct == True:
            self.mp_hdr_sz = self.MH_TINYFREE_SZ
            if self.SIZE_SZ == 4:
                (self.alloc_pc,
                self.free_pc) = struct.unpack_from("<II", mem, 0)
            elif self.SIZE_SZ == 8:
                (self.alloc_pc,
                self.free_pc) = struct.unpack_from("<QQ", mem, 0)

        else:
            # this is to deal with when the allocator
            # is not aware if the chunk is allocated, etc.
            # or when we instantiate an mp_header without
            # any allocator context
            # So we have to try to guess what is the actual mp_header format
            print("[libmempool] Trying to guess the format of the mp_header")

            if self.SIZE_SZ == 4:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc,
                ) = struct.unpack_from("<8I", mem, 0)
            elif self.SIZE_SZ == 8:
                (self.mh_magic,
                self.mh_len,
                self.mh_refcount,
                self.mh_unused,
                self.mh_fd_link,
                self.mh_bk_link,
                self.alloc_pc,
                self.free_pc) = struct.unpack_from("<IIIIQQQQ", mem, 0)

            # We have to do a special test here to see if we are allocated or free.
            # Also the structure placement when free is dependent on the parent
            # size of the chunk on some heaps. Like > 256 chunk will be a tree
            # chunk on dlmalloc, which has an extra 0x10 bytes of overhead. We try
            # to work out where we are without relying explicitly on the parent
            # heap.
            if self.mh_magic == self.INUSE_MAGIC:
                self.inuse = True
                self.mp_hdr_sz = self.MH_INUSE_SZ
            elif self.mh_refcount == self.FREE_MAGIC:
                self.inuse = False
                self.mp_hdr_sz = self.MH_FREE_SZ
            elif self.alloc_pc == self.FREE_MAGIC:
                self.tiny_free_struct = True
                self.mp_hdr_sz = self.MH_TINYFREE_SZ
            else:
                # we haven't found the magic but we are going to trust the caller that
                # indicated if the chunk is inuse
                if self.inuse != None:
                    if self.inuse == True:
                        self.mp_hdr_sz = self.MH_INUSE_SZ
                    else:
                        # assume a regular free, not tiny?
                        self.mp_hdr_sz = self.MH_FREE_SZ
                else:
                    # if we don't find the magic, we assume this dlmalloc/ptmalloc chunk
                    # has been allocated by a non cisco-wrapped allocation function
                    self.mp_hdr_sz = 0
                    self.initOK = False
                    return

    # XXX - fix me
    def info(self):
        if self.address == None:
            addr = 0x0
        else:
            addr = self.address
        # Note: mh_len is 4 bytes hence 8 hex digits but usually we are dealing
        # with smaller sizes so it gives a better output
        return "mh @ 0x%.08x - mh_len: 0x%.04x, alloc_pc: 0x%.08x,%s" % (addr, self.mh_len, self.alloc_pc, self.retsync_rln(self.alloc_pc))

    def check_mh_header_magic(self, addr):
        # XXX - This should call into libmempool_gdb
        try:
            import gdb
            mem = self.inferior.read_memory(addr, 0x4)
        except (NameError, TypeError):
            return "unmapped"
        except gdb.MemoryError:
            return "unmapped"
        magic = struct.unpack_from("<I", mem, 0)[0]
        if magic == self.INUSE_MAGIC or magic == self.FREE_MAGIC:
            return "OK"
        return "-"

    def retsync_rln(self, addr):
        global rln, ret_sync, symbols_cache, symbols_cache_file

        if not addr:
            return "-"

        if ret_sync == RETSYNC_NONE:
            return "-"
        elif ret_sync == RETSYNC_JSON_PROTO:
            if not rln:
                logmsg("WARNING: you need to call libmempool.init_sync() first to use ret-sync")
                ret_sync = False
                return "-"
            if addr in symbols_cache.keys():
                return symbols_cache[addr]
            else:
                sym = rln.invoke(addr)
                symbols_cache[addr] = sym
                if symbols_cache_file != None:
                    pickle.dump(symbols_cache, open(symbols_cache_file, "wb"))
                return sym
        elif ret_sync == RETSYNC_GDB_COMMAND:
            return self.retsync_rln_gdb(addr)
        else:
            return "-"

    # old way of retrieving a symbol
    def retsync_rln_gdb(self, addr):
        # XXX - Prefer not to use a global
        if addr == 0x0:
            return "-"

        try:
            res = gdb.execute("rln 0x%x" % addr, to_string=True)
        except NameError:
            return "-"
        # gdb.error can't be in a tuple because it causes a gdb.name error
        # itself
        except gdb.error:
            # Assume retsync isn't setup
            return "-"
        #print(res)
        if "[sync] process not synced, command is dropped" in res or \
           "[sync] tunnel_send: tunnel is unavailable (did you forget to sync ?)" in res:
            return "unsynced"
        L = res.split()
        if L[-1] == "symbol:":
            # no response from retsync
#            symbol_cache[addr] = "-"
            return "-"
        else:
#            symbol_cache[addr] = L[-1]
            return L[-1]

    def __str__(self):
        if self.mh_version == MEMPOOL_VERSION_1:
            return self.str_v1()
        else:
            return self.str_v2()

    def str_v1(self):

        # XXX: depending if we are 32-bit or 64-bit we should print 8 chars or 16
        #      chars for all pointers so we don't get 0x86887bd on 32-bit
        #      but instead 0x086887bd for instance
        if self.inuse:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:13} = ".format("mh_magic")
            ret += "{:#x}".format(self.mh_magic)
            ret += "\n{:13} = ".format("mh_len")
            ret += "{:#x}".format(self.mh_len)
            ret += "\n{:13} = ".format("mh_refcount")
            ret += "{:#x}".format(self.mh_refcount)
            ret += "\n{:13} = ".format("mh_fd_link")
            ret += "{:#x}".format(self.mh_fd_link)
            if self.check:
                ret += " ({:s})".format(self.check_mh_header_magic(self.mh_fd_link))
            ret += "\n{:13} = ".format("mh_bk_link")
            ret += "{:#x}".format(self.mh_bk_link)
            if self.check:
                ret += " ({:s})".format(self.check_mh_header_magic(self.mh_bk_link))
            ret += "\n{:13} = ".format("alloc_pc")
            ret += "{:#x}".format(self.alloc_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            ret += "\n{:13} = ".format("mh_unused1")
            ret += "{:#x}".format(self.mh_unused1)
            ret += "\n{:13} = ".format("mh_unused2")
            ret += "{:#x}".format(self.mh_unused2)

            return ret
        elif self.free_struct == True:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            if self.chunksz - self.hdr_sz >= 4:
                ret += "\n{:13} = ".format("mh_refcount")
                ret += "{:#x}".format(self.mh_refcount)
            if self.chunksz - self.hdr_sz >= 8 + (1*self.SIZE_SZ):
                ret += "\n{:13} = ".format("mh_fd_link")
                ret += "{:#x}".format(self.mh_fd_link)
                if self.check:
                    ret += " ({:s})".format(self.check_mh_header_magic(self.mh_fd_link))
            if self.chunksz - self.hdr_sz >= 8 + (2*self.SIZE_SZ):
                ret += "\n{:13} = ".format("mh_bk_link")
                ret += "{:#x}".format(self.mh_bk_link)
                if self.check:
                    ret += " ({:s})".format(self.check_mh_header_magic(self.mh_bk_link))
            if self.chunksz - self.hdr_sz >= 8 + (3*self.SIZE_SZ):
                ret += "\n{:13} = ".format("alloc_pc")
                ret += "{:#x}".format(self.alloc_pc)
                if self.check:
                    ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            ret += "\n{:13} = ".format("mh_unused1")
            ret += "{:#x}".format(self.mh_unused1)
            ret += "\n{:13} = ".format("mh_unused2")
            ret += "{:#x}".format(self.mh_unused2)

            return ret
        elif self.tiny_free_struct == True:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:13} = ".format("alloc_pc")
            ret += "{:#x}".format(self.alloc_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            ret += "\n{:13} = ".format("free_pc")
            ret += "{:#x}".format(self.free_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.free_pc))
            return ret
        else:
            print("[libmempool] Unknown mp_header type")
            return("")

    def str_v2(self):
        # XXX: depending if we are 32-bit or 64-bit we should print 8 chars or 16
        #      chars for all pointers so we don't get 0x86887bd on 32-bit
        #      but instead 0x086887bd for instance
        if self.inuse:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:13} = ".format("mh_magic")
            ret += "{:#x}".format(self.mh_magic)
            ret += "\n{:13} = ".format("mh_len")
            ret += "{:#x}".format(self.mh_len)
            ret += "\n{:13} = ".format("mh_refcount")
            ret += "{:#x}".format(self.mh_refcount)
            ret += "\n{:13} = ".format("mh_unused")
            ret += "{:#x}".format(self.mh_unused)
            ret += "\n{:13} = ".format("mh_fd_link")
            ret += "{:#x}".format(self.mh_fd_link)
            if self.check:
                ret += " ({:s})".format(self.check_mh_header_magic(self.mh_fd_link))
            ret += "\n{:13} = ".format("mh_bk_link")
            ret += "{:#x}".format(self.mh_bk_link)
            if self.check:
                ret += " ({:s})".format(self.check_mh_header_magic(self.mh_bk_link))
            ret += "\n{:13} = ".format("alloc_pc")
            ret += "{:#x}".format(self.alloc_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            ret += "\n{:13} = ".format("free_pc")
            ret += "{:#x}".format(self.free_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.free_pc))
            return ret
        elif self.free_struct == True:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            if self.chunksz - self.hdr_sz >= 4:
                ret += "\n{:13} = ".format("mh_refcount")
                ret += "{:#x}".format(self.mh_refcount)
            if self.chunksz - self.hdr_sz >= 8:
                ret += "\n{:13} = ".format("mh_unused")
                ret += "{:#x}".format(self.mh_unused)
            if self.chunksz - self.hdr_sz >= 8 + (1*self.SIZE_SZ):
                ret += "\n{:13} = ".format("mh_fd_link")
                ret += "{:#x}".format(self.mh_fd_link)
                if self.check:
                    ret += " ({:s})".format(self.check_mh_header_magic(self.mh_fd_link))
            if self.chunksz - self.hdr_sz >= 8 + (2*self.SIZE_SZ):
                ret += "\n{:13} = ".format("mh_bk_link")
                ret += "{:#x}".format(self.mh_bk_link)
                if self.check:
                    ret += " ({:s})".format(self.check_mh_header_magic(self.mh_bk_link))
            if self.chunksz - self.hdr_sz >= 8 + (3*self.SIZE_SZ):
                ret += "\n{:13} = ".format("alloc_pc")
                ret += "{:#x}".format(self.alloc_pc)
                if self.check:
                    ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            if self.chunksz - self.hdr_sz >= 8 + (4*self.SIZE_SZ):
                ret += "\n{:13} = ".format("free_pc")
                ret += "{:#x}".format(self.free_pc)
                if self.check:
                    ret += " ({:s})".format(self.retsync_rln(self.free_pc))
            return ret
        elif self.tiny_free_struct == True:
            ret = "struct mp_header @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:13} = ".format("alloc_pc")
            ret += "{:#x}".format(self.alloc_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.alloc_pc))
            ret += "\n{:13} = ".format("free_pc")
            ret += "{:#x}".format(self.free_pc)
            if self.check:
                ret += " ({:s})".format(self.retsync_rln(self.free_pc))
            return ret
        else:
            print("[libmempool] Unknown mp_header type")
            return("")

#     def walk_inuse_list(self, chunk_addr):
#         mh_bk_linkc = chunk_addr + OWNER_CHUNK_SIZE
#         while mh_bk_linkc != 0:
#              chunk_addr = mh_bk_linkc - OWNER_CHUNK_SIZE
#              inf = self.get_chunk_infos(chunk_addr)
#              if inf == None:
#                 print("[libmempool] no chunk info")
#                 break
#              chunk_addr, chunk_size, mh_len, cinuse, pinuse, mh_fd_link_alloc, footer= inf
#              print(display_chunk(chunk_addr, chunk_size, chunk_addr + OWNER_CHUNK_SIZE + INUSE_HEADER_SIZE, mh_len, cinuse, pinuse, footer))
#              mh_bk_linkc = self.get_ptr_value_at_addr(chunk_addr + OWNER_CHUNK_SIZE + INUSE_OFFSET_PREV_ALLOC)

### XXX - Not sure if we should include the following 3 types yet

# XXX - Variable names could be better
class mempool_list(mp_helper):
    "python representation of a struct mempool_list"

    def __init__(self, addr=None):
        super(mempool_list, self).__init__()

        self.offset = 0
        self.head = 0
        self.unk = 0
        self.address = addr

        inferior = get_inferior()
        if inferior == -1:
            print("No inferior")
            return None

        if type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                print('The head argument MUST be either an address or a register (+ optional offset)"')
                return
            addr = res[0] + res[1]
        self.obj_addr = addr

        try:
            if self.SIZE_SZ == 4:
                mem = inferior.read_memory(addr, 0xC)
            elif self.SIZE_SZ == 8:
                mem = inferior.read_memory(addr, 0x18)
        except TypeError:
            self.logmsg("Invalid address specified.")
            return None
        except RuntimeError:
            self.logmsg("Could not read address {0:#x}".format(addr))
            return None

        if self.SIZE_SZ == 4:
            (self.offset,         \
            self.head, \
            self.unk)          = struct.unpack_from("<III", mem, 0x0)
        elif self.SIZE_SZ == 8:
            (self.offset,         \
            self.head, \
            self.unk)          = struct.unpack_from("<QQQ", mem, 0x0)

    def __str__(self):
        ret = "struct mempool_list @ {:#x} ".format(self.obj_addr)
        ret += "{"
        ret += "\n offset       = {:#x}".format(self.offset)
        ret += "\n head         = {:#x}".format(self.head)
        ret += "\n unk          = {:#x}".format(self.unk)
        mempool_addr = self.head
        head_addr = self.obj_addr + self.SIZE_SZ
        while mempool_addr != head_addr:
            ret += "\n"
            nextm = mempool(addr=(mempool_addr-self.offset), offset=self.offset)
            ret += str(nextm)
            mempool_addr = nextm.next
        return ret

################################################################################
class mempool(mp_helper):
    "python representation of a struct mempool"

    def __init__(self, addr=None, offset=0):
        super(mempool, self).__init__()

        self.dlmstate = 0
        self.pool_name = ""
        self.field_58 = 0
        self.mempool_id = 0
        self.field_60 = ""
        self.next = 0
        self.offset = offset

        inferior = get_inferior()
        if inferior == -1:
            print("No inferior")
            return None

        if type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                print('The first argument MUST be either an address or a register (+ optional offset)"')
                return
            addr = res[0] + res[1]
        self.obj_addr = addr

        try:
            mem = inferior.read_memory(addr, self.offset + self.SIZE_SZ)
        except TypeError:
            self.logmsg("Invalid address specified.")
            return None
        except RuntimeError:
            self.logmsg("Could not read address {0:#x}".format(addr))
            return None

        if self.SIZE_SZ == 4:
            (self.dlmstate,
            self.pool_name,
            self.field_54,
            self.mempool_id,
            self.field_60,
            self.next) = struct.unpack_from("<I80sII12sI", mem, 0x0)
        elif self.SIZE_SZ == 8:
            if self.offset == 0x90:
                (self.dlmstate,
                self.pool_name,
                self.field_58,
                self.mempool_id,
                self.field_60,
                self.next) = struct.unpack_from("<Q80sII48sQ", mem, 0x0)
            elif self.offset == 0x78:
                (self.dlmstate,
                self.pool_name,
                self.field_58,
                self.mempool_id,
                self.field_60,
                self.next) = struct.unpack_from("<Q80sII24sQ", mem, 0x0)
            else:
                print("Unknown size for 64-bit mempool: 0x%x" % self.offset+self.SELF_SZ)

    def __str__(self):
        ret = "struct mempool @ {:#x} ".format(self.obj_addr)
        ret += "{"
        ret += "\n dlmstate      = {:#x}".format(self.dlmstate)
        ret += "\n pool_name     = {:s}".format(self.pool_name.decode().rstrip('\0'))
        ret += "\n field_58      = {:#x}".format(self.field_58)
        ret += "\n mempool_id    = {:#x}".format(self.mempool_id)
        #ret += "\n field_60      = {:s}".format(self.field_60)
        ret += "\n next          = {:#x}".format(self.next)
        return ret

if __name__ == "__main__":
    mp_helper.logmsg("loaded")
