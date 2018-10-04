#include <linux/inetdevice.h>
#include <net/ip_fib.h>
#include <net/route.h>

__be32 fib_compute_spec_dst(struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    struct in_device *in_dev;
    struct fib_result res;
    struct rtable *rt;
    struct flowi4 fl4;
    struct net *net;
    int scope;

    rt = skb_rtable(skb);
    if ((rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST | RTCF_LOCAL)) ==
        RTCF_LOCAL)
        return ip_hdr(skb)->daddr;

    in_dev = __in_dev_get_rcu(dev);
    BUG_ON(!in_dev);

    net = dev_net(dev);

    scope = RT_SCOPE_UNIVERSE;
    if (!ipv4_is_zeronet(ip_hdr(skb)->saddr)) {
        fl4.flowi4_oif = 0;
        fl4.flowi4_iif = LOOPBACK_IFINDEX;
        fl4.daddr = ip_hdr(skb)->saddr;
        fl4.saddr = 0;
        fl4.flowi4_tos = RT_TOS(ip_hdr(skb)->tos);
        fl4.flowi4_scope = scope;
        fl4.flowi4_mark = IN_DEV_SRC_VMARK(in_dev) ? skb->mark : 0;
        flowi4_tun_id_set(&fl4, 0);
        if (!fib_lookup(net, &fl4, &res))
            return FIB_RES_PREFSRC(net, res);
    } else {
        scope = RT_SCOPE_LINK;
    }

    return inet_select_addr(dev, ip_hdr(skb)->saddr, scope);
}
