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
};

static struct genl_family net_drop_monitor_family;

static DEFINE_PER_CPU(struct per_cpu_dm_data, dm_cpu_data);

static const struct genl_ops dropmon_ops[] = {};

static struct genl_family net_drop_monitor_family = {
    .hdrsize        = 0,
    .name           = "NET_DM",
    .version        = 2,
    .module		= THIS_MODULE,
    .ops		= dropmon_ops,
    .n_ops		= ARRAY_SIZE(dropmon_ops),
};

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

static int init_net_drop_monitor(void)
{
    struct per_cpu_dm_data *data;
    int cpu, rc;

    pr_info("Initializing network drop monitor service\n");

    rc = genl_register_family(&net_drop_monitor_family);
    if (rc) {
        pr_err("Could not create drop monitor netlink family\n");
        return rc;
    }

    rc = 0;

    for_each_possible_cpu(cpu) {
        data = &per_cpu(dm_cpu_data, cpu);
        spin_lock_init(&data->lock);
    }

    goto out;

out_unreg:
    genl_unregister_family(&net_drop_monitor_family);
out:
    return rc;
}

static void exit_net_drop_monitor(void)
{
    struct per_cpu_dm_data *data;
    int cpu;

    for_each_possible_cpu(cpu) {
        data = &per_cpu(dm_cpu_data, cpu);
        kfree_skb(data->skb);
    }

    BUG_ON(genl_unregister_family(&net_drop_monitor_family));
}

static int __init lp_tcp_init(void)
{
    int rc;

    rc = init_net_drop_monitor();
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
        return ret;
    }

    return 0;
}

static void __exit lp_tcp_exit(void)
{
    exit_net_drop_monitor();
    WARN_ON(klp_unregister_patch(&patch));
}

module_init(lp_tcp_init);
module_exit(lp_tcp_exit);
MODULE_AUTHOR("Zwb <ethercflow@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_INFO(livepatch, "Y");
