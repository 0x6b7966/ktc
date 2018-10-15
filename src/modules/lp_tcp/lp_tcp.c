#include <linux/module.h>
#include <linux/livepatch.h>
#include <linux/netlink.h>
#include <linux/percpu.h>
#include <net/genetlink.h>

#include "sock.c"
#include "fib_frontend.c"
#include "fib_semantics.c"
#include "ip_output.c"
#include "ip_options.c"
#include "ip_sockglue.c"
#include "icmp.c"
#include "route.c"
#include "tcp_ipv4.c"

struct per_cpu_dm_data {
    spinlock_t		lock;
    struct sk_buff		*skb;
    struct work_struct	dm_alert_work;
    struct timer_list	send_timer;
};

struct tcp_dm_drop_point {
    __u8 pc[8];
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

static struct genl_family tcp_drop_monitor_family;

static DEFINE_PER_CPU(struct per_cpu_dm_data, dm_cpu_data);

static const struct genl_ops dropmon_ops[] = {};

static struct genl_family tcp_drop_monitor_family = {
    .hdrsize            = 0,
    .name               = "TCP_DM",
    .version            = 2,
    .module		= THIS_MODULE,
    .ops		= dropmon_ops,
    .n_ops		= ARRAY_SIZE(dropmon_ops),
};

static int dm_hit_limit = 64;

static struct klp_func funcs[] = {
    {
        .old_name = "tcp_v4_rcv",
        .new_func = lp_tcp_v4_rcv,
    }, { }
};

static struct klp_object objs[] = {
    {
        .funcs = funcs,
    }, { }
};

static struct klp_patch patch = {
    .mod = THIS_MODULE,
    .objs = objs,
};

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

static void send_dm_alert(struct work_struct *work)
{
    struct sk_buff *skb;
    struct per_cpu_dm_data *data;

    data = container_of(work, struct per_cpu_dm_data, dm_alert_work);

    skb = reset_per_cpu_data(data);

    if (skb)
        genlmsg_multicast(&tcp_drop_monitor_family, skb, 0,
                  0, GFP_KERNEL);
}

static void sched_send_work(unsigned long _data)
{
    struct per_cpu_dm_data *data = (struct per_cpu_dm_data *)_data;

    schedule_work(&data->dm_alert_work);
}

static int init_tcp_drop_monitor(void)
{
    struct per_cpu_dm_data *data;
    int cpu, rc;

    pr_info("Initializing tcp layer drop monitor service\n");

    rc = genl_register_family(&tcp_drop_monitor_family);
    if (rc) {
        pr_err("Could not create drop monitor tcp layer family\n");
        return rc;
    }

    rc = 0;

    for_each_possible_cpu(cpu) {
        data = &per_cpu(dm_cpu_data, cpu);
        INIT_WORK(&data->dm_alert_work, send_dm_alert);
        init_timer(&data->send_timer);
        data->send_timer.data = (unsigned long)data;
        data->send_timer.function = sched_send_work;
        spin_lock_init(&data->lock);
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

static int __init lp_tcp_init(void)
{
    int rc;

    rc = init_tcp_drop_monitor();
    if (rc)
        return rc;

    if (!klp_have_reliable_stack() && !patch.immediate) {
        patch.immediate = true;
        pr_notice("The consistency model isn't supported for your architecture. "
                  "Bypassing safety mechanisms and applying the patch immediately.\n");
    }

    rc = klp_register_patch(&patch);
    if (rc)
        return rc;
    rc = klp_enable_patch(&patch);
    if (rc) {
        WARN_ON(klp_unregister_patch(&patch));
        return rc;
    }

    return 0;
}

static void __exit lp_tcp_exit(void)
{
    exit_tcp_drop_monitor();
    WARN_ON(klp_unregister_patch(&patch));
}

module_init(lp_tcp_init);
module_exit(lp_tcp_exit);
MODULE_AUTHOR("Zwb <ethercflow@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_ALIAS_GENL_FAMILY("TCP_DM");
MODULE_INFO(livepatch, "Y");
