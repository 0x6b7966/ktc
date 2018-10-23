#ifndef __TCP_DROPMON_H
#define __TCP_DROPMON_H

#include <linux/types.h>
#include <linux/netlink.h>

struct tcp_dm_drop_point {
	__u8 pc[8];
	__u32 count;
};

#define is_drop_point_hw(x) do {\
	int ____i, ____j;\
	for (____i = 0; ____i < 8; i ____i++)\
		____j |= x[____i];\
	____j;\
} while (0)

#define TCP_DM_CFG_VERSION  0
#define TCP_DM_CFG_ALERT_COUNT  1
#define TCP_DM_CFG_ALERT_DELAY 2
#define TCP_DM_CFG_MAX 3

struct tcp_dm_config_entry {
	__u32 type;
	__u64 data __attribute__((aligned(8)));
};

struct tcp_dm_config_msg {
	__u32 entries;
	struct tcp_dm_config_entry options[0];
};

struct tcp_dm_alert_msg {
	__u32 entries;
	struct tcp_dm_drop_point points[0];
};

struct tcp_dm_user_msg {
	union {
		struct tcp_dm_config_msg user;
		struct tcp_dm_alert_msg alert;
	} u;
};


/* These are the netlink message types for this protocol */

enum {
	TCP_DM_CMD_UNSPEC = 0,
	TCP_DM_CMD_ALERT,
	_TCP_DM_CMD_MAX,
};

#define TCP_DM_CMD_MAX (_TCP_DM_CMD_MAX - 1)

/*
 * Our group identifiers
 */
#define TCP_DM_GRP_ALERT 5
#endif
