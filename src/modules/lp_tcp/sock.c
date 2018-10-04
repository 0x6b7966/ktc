#include <linux/inetdevice.h>

#define _SK_MEM_PACKETS        256
#define _SK_MEM_OVERHEAD    SKB_TRUESIZE(256)
#define SK_WMEM_MAX        (_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

__u32 sysctl_wmem_default __read_mostly = SK_WMEM_MAX;

