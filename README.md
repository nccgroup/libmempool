# libmempool

Preliminary note: we recommend you to use this as part of 
[asatools](https://github.com/nccgroup/asatools) but it can also be used 
standalone.

**libmempool** is a python script and GDB analysis tool to aid in the analysis
of mempool-related data structuress found inside various heaps on Cisco ASA
devices. Normally this information is embedded into a heap chunk, or is a
custom extension to some other common heap structure such as a dlmalloc
`mstate` structure. 

Cisco uses the term mempool to describe regions of memory mapped for various
purposes such as general allocations, DMA, etc. These regions typically contain
their heap, such as dlmalloc. Allocations routines on these mempools are
typically done using wrappers around the underyling heap allocator, and these
wrappers inject mempool-specific metadata into the resulting allocations. We
refer to this metadata as a *mempool header* or *mh* for short. Similarly we
regularly will refer to a *mempool* as *mp*. The use of *mh* to describe a
*mempool header* is also consistent with various strings found in the Cisco ASA
*lina* binaries.

Although libmempool can be used as a stand-alone tool for analyzing some things
related to mempool headers and data structures, it's greatest value comes from
being used as a callback from other libraries such as
[libdlmalloc](https://github.com/nccgroup/libdlmalloc) or
[libptmalloc](https://github.com/nccgroup/libdlmalloc). 

It's worth noting that certain aspects of the mempool, such as the bins used to
track in-use chunks, are embedded inside an dlmalloc 2.8.x mstate structure and
follow the same bin sizing. This means almost inevitably you may to poke around
at least the mstate encapsulating the mempool data using libdlmalloc.

## Supported versions

libmempool has been tested with 32-bit / 64-bit Cisco ASA versions (both
ASA5500-X series and GNS3) that use dlmalloc2.8 or glibc's ptmalloc2-based
allocator. It has been tested on numerous ASA versions, including numerous
8.x.y and 9.x.y branches. However, it is entirely possible that it will break
on some version.

## Installation

To use libmempool stand-alone you simply need to import the `libmempool.py`
file into your project. This allows you to do some limited actions, like
register the *mpcallback* object, etc. This can be useful if you're doing
offline analysis of logged heap functionality.

To import into GDB, the script just requires GDB with python support. Although
most modern GDB versions have moved towards python 3, some still expect 2.7.
The script has been tested on both, but primarily development and testing is
done with python 3.

```
(gdb) source libmempool_gdb.py
```

We separate most of the gdb-related logic out of libmempool.py into
libmempool_gdb.py just to test abstracting things and so that you can easily
use libmempool.py outside of GDB. This will likely change in the future, as we
will eventually want to implement similar debug engine abstractions used by
other heap analysis tools like libheap and shadow.

## Usage

Although much of the value of libmempool comes from the `mpcallback` callback
function it exposes, there are a number of built-in GDB commands we can look
at.

```
(gdb) mphelp 
[libmempool] mempool commands for gdb
[libmempool] mpheader -v -x <addr>           : show chunk contents (-v for verbose, -x for data dump)
[libmempool] mpbinwalk [-v] [-p <addr>] <sz> : walk an mpbin and operate on each chunk in a bin
[libmempool] mpbin <addr>                    : determine to which bin an mp_header is associated to
[libmempool] mpmstate <addr>                 : display and cache a mempool mstate address
[libmempool] mphelp
```

Assuming we know the address of some mempool header, we can analyze it's data.
Note this must be the address of the mempool header itself, and not the address
of the core allocators chunk metadata. So, we can dump the contents as follows:

```
(gdb) mpheader 0x7fffbc1c1ca0
struct mp_header @ 0x7fffbc1c1ca0 {
mh_magic      = 0xa11c0123
mh_len        = 0x3
mh_refcount   = 0x10000
mh_unused     = 0x0
mh_fd_link    = 0x7fffbc1c19e0 (OK)
mh_bk_link    = 0x7ffff7ff7540 (-)
alloc_pc      = 0x55555849e260 (-)
free_pc       = 0x0 (-)
```

We can also dump the hex contents of the chunk using `-x`.

```
(gdb) mpheader -x 0x7fffbc1c1ca0 
struct mp_header @ 0x7fffbc1c1ca0 {
mh_magic      = 0xa11c0123
mh_len        = 0x3
mh_refcount   = 0x10000
mh_unused     = 0x0
mh_fd_link    = 0x7fffbc1c19e0 (OK)
mh_bk_link    = 0x7ffff7ff7540 (-)
alloc_pc      = 0x55555849e260 (-)
free_pc       = 0x0 (-)
0x3 bytes of chunk data:
0x7fffbc1c1cd0:	0x55	0x04	0x03
```

Mempools have the concept of bins, which are doubley linked lists sized
the same as dlmalloc bins, but that are are used track inuse chunks rather
than free chunks. This is done for memory usage bookkeeping on Cisco devices.
Often times you might find a chunk that contains a mempool header, but you
don't yet know where the mstate structure on the heap lives. To get your
bearings, you can use the `mpbin` command, which will give you the address of
the mempool bin that an inuse chunk currently lives in. For instance:

```
(gdb) mpbin 0x7fffbc1c1ca0 
[libmempool] Found bin start at 0x7ffff7ff7540
[libmempool] Cached new mp_mstate @ 0x7ffff7ff73c0
[libmempool] mp_smallbin[08] - sz: 0x00000040 cnt: 0x00d3, mh_fd_link: 0x7fffbc1c1ca0
```

This note only found the start of the mempool portion of the mstate, but also
cached it, and lists the specific bin that the chunk exists in. We could
optionally use the `mpbinwalk` command to list all 0xd3 chunks from this bin,
or only up to a specific number:

```
(gdb) mpbinwalk 0x40
[libmempool] mp_header @ 0x7ffff7ff7540 - mh_len: 0x00000000, alloc_pc: 0x00000000 [BIN HEAD]
[libmempool] mp_header @ 0x7fffbc1c1ca0 - mh_len: 0x00000003, alloc_pc: 0x55555849e260
[libmempool] mp_header @ 0x7fffbc1c19e0 - mh_len: 0x00000003, alloc_pc: 0x55555849e260
[libmempool] mp_header @ 0x7fffbc1c1750 - mh_len: 0x00000003, alloc_pc: 0x55555849e260
[libmempool] mp_header @ 0x7fffbc1bffa0 - mh_len: 0x00000003, alloc_pc: 0x55555849e260
[libmempool] mp_header @ 0x7fffbc1bff60 - mh_len: 0x00000003, alloc_pc: 0x5555584a1288
[libmempool] mp_header @ 0x7fffbc1c0050 - mh_len: 0x00000003, alloc_pc: 0x55555849e260
[...]
```

Now if we want to dump the whole mempool portion of the mstate structure (so
all of the bins and related stats) we can use the `mpmstate` command:

```
(gdb) mpmstate 0x7ffff7ff73c0
struct mp_mstate @ 0x7ffff7ff73c0 {
mp_smallbin[00] - sz: 0x00000000 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[01] - sz: 0x00000008 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[02] - sz: 0x00000010 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[03] - sz: 0x00000018 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[04] - sz: 0x00000020 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[05] - sz: 0x00000028 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[06] - sz: 0x00000030 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[07] - sz: 0x00000038 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[08] - sz: 0x00000040 cnt: 0x00d3, mh_fd_link: 0x7fffbc1c1ca0
mp_smallbin[09] - sz: 0x00000048 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[10] - sz: 0x00000050 cnt: 0x0429, mh_fd_link: 0x7fffa4000d10
mp_smallbin[11] - sz: 0x00000058 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[12] - sz: 0x00000060 cnt: 0x335d, mh_fd_link: 0x7fffb80064b0
mp_smallbin[13] - sz: 0x00000068 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[14] - sz: 0x00000070 cnt: 0x073a, mh_fd_link: 0x7fffbc1c7260
mp_smallbin[15] - sz: 0x00000078 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[16] - sz: 0x00000080 cnt: 0x0301, mh_fd_link: 0x7fffbc1c72d0
mp_smallbin[17] - sz: 0x00000088 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[18] - sz: 0x00000090 cnt: 0x0c98, mh_fd_link: 0x7fffc9488920
mp_smallbin[19] - sz: 0x00000098 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[20] - sz: 0x000000a0 cnt: 0x0161, mh_fd_link: 0x7fffa40009a0
mp_smallbin[21] - sz: 0x000000a8 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[22] - sz: 0x000000b0 cnt: 0x0092, mh_fd_link: 0x7fffa4000a40
mp_smallbin[23] - sz: 0x000000b8 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[24] - sz: 0x000000c0 cnt: 0x0120, mh_fd_link: 0x7fffbc1c1270
mp_smallbin[25] - sz: 0x000000c8 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[26] - sz: 0x000000d0 cnt: 0x00ba, mh_fd_link: 0x7fffbc1b51a0
mp_smallbin[27] - sz: 0x000000d8 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[28] - sz: 0x000000e0 cnt: 0x005b, mh_fd_link: 0x7fffc9485020
mp_smallbin[29] - sz: 0x000000e8 cnt: 0x0000, mh_fd_link: 0x0
mp_smallbin[30] - sz: 0x000000f0 cnt: 0x016e, mh_fd_link: 0x7fffbc1c7040
mp_smallbin[31] - sz: 0x000000f8 cnt: 0x0000, mh_fd_link: 0x0
mp_treebin[00] - sz: 0x00000180 cnt: 0x050f, mh_fd_link: 0x7fffbc1c7130
mp_treebin[01] - sz: 0x00000200 cnt: 0x00ce, mh_fd_link: 0x7fffbc1c2610
mp_treebin[02] - sz: 0x00000300 cnt: 0x011a, mh_fd_link: 0x7fffa40053c0
mp_treebin[03] - sz: 0x00000400 cnt: 0x013e, mh_fd_link: 0x7fffa4000f80
mp_treebin[04] - sz: 0x00000600 cnt: 0x016f, mh_fd_link: 0x7fffbc1c2a80
mp_treebin[05] - sz: 0x00000800 cnt: 0x009a, mh_fd_link: 0x7fffbc1b4880
mp_treebin[06] - sz: 0x00000c00 cnt: 0x0081, mh_fd_link: 0x7fffbc1b38b0
mp_treebin[07] - sz: 0x00001000 cnt: 0x002b, mh_fd_link: 0x7fffbc1b2330
mp_treebin[08] - sz: 0x00001800 cnt: 0x0326, mh_fd_link: 0x7fffc9368e10
mp_treebin[09] - sz: 0x00002000 cnt: 0x0038, mh_fd_link: 0x7fffc92e9c60
mp_treebin[10] - sz: 0x00003000 cnt: 0x00b9, mh_fd_link: 0x7fffa4003380
mp_treebin[11] - sz: 0x00004000 cnt: 0x006d, mh_fd_link: 0x7fffc9457720
mp_treebin[12] - sz: 0x00006000 cnt: 0x023b, mh_fd_link: 0x7fffbc1ac000
mp_treebin[13] - sz: 0x00008000 cnt: 0x0018, mh_fd_link: 0x7fffc946f850
mp_treebin[14] - sz: 0x0000c000 cnt: 0x0030, mh_fd_link: 0x7fffc935fcc0
mp_treebin[15] - sz: 0x00010000 cnt: 0x0019, mh_fd_link: 0x7fffb44262b0
mp_treebin[16] - sz: 0x00018000 cnt: 0x0073, mh_fd_link: 0x7fffc93fe020
mp_treebin[17] - sz: 0x00020000 cnt: 0x0018, mh_fd_link: 0x7fffc94368f0
mp_treebin[18] - sz: 0x00030000 cnt: 0x000c, mh_fd_link: 0x7fffb0665010
mp_treebin[19] - sz: 0x00040000 cnt: 0x001c, mh_fd_link: 0x7fffa836d010
mp_treebin[20] - sz: 0x00060000 cnt: 0x000d, mh_fd_link: 0x7fffa8c55010
mp_treebin[21] - sz: 0x00080000 cnt: 0x001d, mh_fd_link: 0x7fffa9009010
mp_treebin[22] - sz: 0x000c0000 cnt: 0x0006, mh_fd_link: 0x7fffa9081010
mp_treebin[23] - sz: 0x00100000 cnt: 0x000a, mh_fd_link: 0x7fffb025f010
mp_treebin[24] - sz: 0x00180000 cnt: 0x000b, mh_fd_link: 0x7fffa8b38010
mp_treebin[25] - sz: 0x00200000 cnt: 0x000e, mh_fd_link: 0x7fffb008a010
mp_treebin[26] - sz: 0x00300000 cnt: 0x0007, mh_fd_link: 0x7fffb0323010
mp_treebin[27] - sz: 0x00400000 cnt: 0x0002, mh_fd_link: 0x7fffa87f5010
mp_treebin[28] - sz: 0x00600000 cnt: 0x0003, mh_fd_link: 0x7fffa83e9010
mp_treebin[29] - sz: 0x00800000 cnt: 0x0001, mh_fd_link: 0x7fffab328010
mp_treebin[30] - sz: 0x00c00000 cnt: 0x0001, mh_fd_link: 0x7fffd706d010
mp_treebin[31] - sz: 0xffffffff cnt: 0x0003, mh_fd_link: 0x7fffa9326010 [UNSORTED]
```

## Callback integration

We implement a dlmalloc and ptmalloc "aware" callback inside libmempool, which
is meant to be called by libdlmalloc or libptmalloc to augment their chunk
annotation with additional mempools-specific data. For instance, if libdlmalloc
is used to print a verbose listing of a dlmalloc chunk, and that chunk holds
inside of it a mempool header, then the mempool callback will print it out.

For information on how this looks when used via other tools, please see the
README files in both libdlmalloc and libptmalloc.

# Future development

We will likely add functionality to libmempool as we need or while doing
future Cisco ASA research. Planned additions currently are:

- Abstract out the debug engine logic to be more like libheap or shadow's newer
  designs
- We don't currently validate the footer inside of a check when analyzing that
  a chunk looks okay, but this should be added.

# Contact

We would love to hear feedback about this tool and also are happy to get pull
requests.

* Aaron Adams
    * Email: `aaron<dot>adams<at>nccgroup<dot>trust`
    * Twitter: @fidgetingbits

* Cedric Halbronn
    * Email: `cedric<dot>halbronn<at>nccgroup<dot>trust`
    * Twitter: @saidelike
