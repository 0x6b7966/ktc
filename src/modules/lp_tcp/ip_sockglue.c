#include <linux/errqueue.h>
#include <net/ip.h>
#include <net/tcp.h>

void ip_local_error(struct sock *sk, int err, __be32 daddr, __be16 port, u32 info)
{
    struct inet_sock *inet = inet_sk(sk);
    struct sock_exterr_skb *serr;
    struct iphdr *iph;
    struct sk_buff *skb;

    if (!inet->recverr)
        return;

    skb = alloc_skb(sizeof(struct iphdr), GFP_ATOMIC);
    if (!skb)
        return;

    skb_put(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    iph->daddr = daddr;

    serr = SKB_EXT_ERR(skb);
    serr->ee.ee_errno = err;
    serr->ee.ee_origin = SO_EE_ORIGIN_LOCAL;
    serr->ee.ee_type = 0;
    serr->ee.ee_code = 0;
    serr->ee.ee_pad = 0;
    serr->ee.ee_info = info;
    serr->ee.ee_data = 0;
    serr->addr_offset = (u8 *)&iph->daddr - skb_network_header(skb);
    serr->port = port;

    __skb_pull(skb, skb_tail_pointer(skb) - skb->data);
    skb_reset_transport_header(skb);

    if (sock_queue_err_skb(sk, skb))
        kfree_skb(skb);
}