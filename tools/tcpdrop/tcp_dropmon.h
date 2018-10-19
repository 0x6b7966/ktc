#ifndef __TCP_DROPMON_H
#define __TCP_DROPMON_H

#include <linux/netlink.h>

struct tcp_dm_drop_point {
    __u8 pc[8];
    __u16 sport;
    __u16 dport;
    __u32 count;
};

struct tcp_dm_alert_msg {
    __u32 entries;
    struct tcp_dm_drop_point points[0];
};

enum {
    TCP_DM_CMD_UNSPEC = 0,
    TCP_DM_CMD_ALERT,
    TCP_DM_CMD_CONFIG,
    TCP_DM_CMD_START,
    TCP_DM_CMD_STOP,
    _TCP_DM_CMD_MAX,
};

#define TCP_DM_CMD_MAX (_TCP_DM_CMD_MAX - 1)

#define TCP_DM_GRP_ALERT 1
#endif // __TCP_DROPMON_H
