#include <linux/types.h>
#include <linux/inetdevice.h>
#include <net/route.h>
#include <net/ip_fib.h>

/*
   We do not cache source address of outgoing interface,
   because it is used only by IP RR, TS and SRR options,
   so that it out of fast path.

   BTW remember: "addr" is allowed to be not aligned
   in IP options!
 */

void ip_rt_get_source(u8 *addr, struct sk_buff *skb, struct rtable *rt)
{
    __be32 src;

    if (rt_is_output_route(rt))
        src = ip_hdr(skb)->saddr;
    else {
        struct fib_result res;
        struct flowi4 fl4;
        struct iphdr *iph;

        iph = ip_hdr(skb);

        memset(&fl4, 0, sizeof(fl4));
        fl4.daddr = iph->daddr;
        fl4.saddr = iph->saddr;
        fl4.flowi4_tos = RT_TOS(iph->tos);
        fl4.flowi4_oif = rt->dst.dev->ifindex;
        fl4.flowi4_iif = skb->dev->ifindex;
        fl4.flowi4_mark = skb->mark;

        rcu_read_lock();
        if (fib_lookup(dev_net(rt->dst.dev), &fl4, &res) == 0)
            src = FIB_RES_PREFSRC(dev_net(rt->dst.dev), res);
        else
            src = inet_select_addr(rt->dst.dev,
                                   rt_nexthop(rt, iph->daddr),
                                   RT_SCOPE_UNIVERSE);
        rcu_read_unlock();
    }
    memcpy(addr, &src, 4);
}
