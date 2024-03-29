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
#include "drop_monitor.c"
#include "tcp_ipv4.c"

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
MODULE_INFO(livepatch, "Y");
