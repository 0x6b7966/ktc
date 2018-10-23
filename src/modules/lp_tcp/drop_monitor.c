#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <linux/netpoll.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/netlink.h>
#include <linux/percpu.h>
#include <linux/timer.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netevent.h>

#include <trace/events/skb.h>
#include <trace/events/napi.h>

#include <asm/unaligned.h>

#include "tcp_dropmon.h"

struct per_cpu_dm_data {
	spinlock_t		lock;
	struct sk_buff		*skb;
	struct work_struct	dm_alert_work;
	struct timer_list	send_timer;
};

struct dm_hw_stat_delta {
	struct net_device *dev;
	unsigned long last_rx;
	struct list_head list;
	struct rcu_head rcu;
	unsigned long last_drop_val;
};

static struct genl_family tcp_drop_monitor_family;

static DEFINE_PER_CPU(struct per_cpu_dm_data, dm_cpu_data);

static int dm_hit_limit = 64;
static int dm_delay = 1;

static struct sk_buff *reset_per_cpu_data(struct per_cpu_dm_data *data)
{
	size_t al;
	struct tcp_dm_alert_msg *msg;
	struct nlattr *nla;
	struct sk_buff *skb;
	unsigned long flags;

	al = sizeof(struct tcp_dm_alert_msg);
	al += dm_hit_limit * sizeof(struct tcp_dm_drop_point);
	al += sizeof(struct nlattr);

	skb = genlmsg_new(al, GFP_KERNEL);

	if (skb) {
		genlmsg_put(skb, 0, 0, &tcp_drop_monitor_family,
				0, TCP_DM_CMD_ALERT);
		nla = nla_reserve(skb, NLA_UNSPEC,
				  sizeof(struct tcp_dm_alert_msg));
		msg = nla_data(nla);
		memset(msg, 0, al);
	} else {
		mod_timer(&data->send_timer, jiffies + HZ / 10);
	}

	spin_lock_irqsave(&data->lock, flags);
	swap(data->skb, skb);
	spin_unlock_irqrestore(&data->lock, flags);

	return skb;
}

static struct genl_multicast_group dropmon_mcgrps[] = {
	{ .name = "events", },
};

static void send_dm_alert(struct work_struct *work)
{
	struct sk_buff *skb;
	struct per_cpu_dm_data *data;

	data = container_of(work, struct per_cpu_dm_data, dm_alert_work);

	skb = reset_per_cpu_data(data);

	if (skb) {
		genlmsg_multicast(&tcp_drop_monitor_family, skb, 0,
				  0, GFP_KERNEL);
	}
}

static void sched_send_work(unsigned long _data)
{
	struct per_cpu_dm_data *data = (struct per_cpu_dm_data *)_data;

	schedule_work(&data->dm_alert_work);
}

void trace_tcp_drop(struct sk_buff *skb, void *location)
{
	struct tcp_dm_alert_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *nla;
	int i;
	struct sk_buff *dskb;
	struct per_cpu_dm_data *data;
	unsigned long flags;

	local_irq_save(flags);
	data = &__get_cpu_var(dm_cpu_data);
	spin_lock(&data->lock);
	dskb = data->skb;

	if (!dskb)
		goto out;

	nlh = (struct nlmsghdr *)dskb->data;
	nla = genlmsg_data(nlmsg_data(nlh));
	msg = nla_data(nla);
	for (i = 0; i < msg->entries; i++) {
		if (!memcmp(&location, msg->points[i].pc, sizeof(void *))) {
			msg->points[i].count++;
			goto out;
		}
	}
	if (msg->entries == dm_hit_limit)
		goto out;

	__nla_reserve_nohdr(dskb, sizeof(struct tcp_dm_drop_point));
	nla->nla_len += NLA_ALIGN(sizeof(struct tcp_dm_drop_point));
	memcpy(msg->points[msg->entries].pc, &location, sizeof(void *));
	msg->points[msg->entries].count = 1;
	msg->entries++;

	if (!timer_pending(&data->send_timer)) {
		data->send_timer.expires = jiffies + dm_delay * HZ;
		add_timer(&data->send_timer);
	}

out:
	spin_unlock_irqrestore(&data->lock, flags);
}

static struct genl_family tcp_drop_monitor_family = {
	.hdrsize        = 0,
	.name           = "TCP_DM",
	.version        = 1,
	.module		= THIS_MODULE,
	.mcgrps		= dropmon_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(dropmon_mcgrps),
};

static int init_tcp_drop_monitor(void)
{
	struct per_cpu_dm_data *data;
	int cpu, rc;

	pr_info("Initializing tcp drop monitor service\n");

	if (sizeof(void *) > 8) {
		pr_err("Unable to store program counters on this arch, Drop monitor failed\n");
		return -ENOSPC;
	}

	rc = genl_register_family(&tcp_drop_monitor_family);
	if (rc) {
		pr_err("Could not create drop monitor netlink family\n");
		return rc;
	}

	WARN_ON(tcp_drop_monitor_family.mcgrp_offset != TCP_DM_GRP_ALERT);

	rc = 0;

	for_each_possible_cpu(cpu) {
		data = &per_cpu(dm_cpu_data, cpu);
		INIT_WORK(&data->dm_alert_work, send_dm_alert);
		init_timer(&data->send_timer);
		data->send_timer.data = (unsigned long)data;
		data->send_timer.function = sched_send_work;
		spin_lock_init(&data->lock);
		reset_per_cpu_data(data);
	}

	goto out;

out:
	return rc;
}

static void exit_tcp_drop_monitor(void)
{
	struct per_cpu_dm_data *data;
	int cpu;

	for_each_possible_cpu(cpu) {
		data = &per_cpu(dm_cpu_data, cpu);
		del_timer_sync(&data->send_timer);
		cancel_work_sync(&data->dm_alert_work);
		kfree_skb(data->skb);
	}

	BUG_ON(genl_unregister_family(&tcp_drop_monitor_family));
}
