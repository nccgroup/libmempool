// compile with -m32 if you want the 32-bit version on 64-bit

#include <unistd.h>
#include <stdio.h>

#define NTREEBINS 32
#define TREEBIN_SHIFT 8

typedef unsigned int bindex_t;         /* Described below */

/* assign tree index for size S to variable I */
#if defined(__GNUC__) && defined(i386)
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K;\
    __asm__("bsrl %1,%0\n\t" : "=r" (K) : "rm"  (X));\
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}
#else
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int Y = (unsigned int)X;\
    unsigned int N = ((Y - 0x100) >> 16) & 8;\
    unsigned int K = (((Y <<= N) - 0x1000) >> 16) & 4;\
    N += K;\
    N += K = (((Y <<= K) - 0x4000) >> 16) & 2;\
    K = 14 - N + ((Y <<= K) >> 15);\
    I = (K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1));\
  }\
}
#endif

int
main(int argc, char ** argv)
{
    int i;
    int idx;
    int last_idx = -1;
    int last_size;
    for (i = 0x100; i < 0x80000000; i += 0x10) {
        compute_tree_index(i, idx);
        if (last_idx != idx) {
            last_idx = idx;
            if (idx != 0) {
                printf("size: 0x%x, index: 0x%x\n", i, idx-1);
            }
        }
    }
    return 0;
}
