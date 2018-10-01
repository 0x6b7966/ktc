#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/livepatch.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/busy_poll.h>
#include <net/ip.h>

#define CREATE_TRACE_POINTS
#include "tcp_trace.h"

#include "ip_output.c"

static int jtcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
    trace_tcp_retransmit_skb(sk, skb);
    jprobe_return();
    return 0;

}

static struct jprobe tcp_retransmit_skb_jp = {
    .kp = {
        .symbol_name = "tcp_retransmit_skb",
    },
    .entry = jtcp_retransmit_skb,
};

static int jtcp_send_loss_probe(struct sock *sk)
{
    trace_tcp_send_loss_probe(sk);
    jprobe_return();
    return 0;
}

static struct jprobe tcp_send_loss_probe_jp = {
    .kp = {
        .symbol_name = "tcp_send_loss_probe",
    },
    .entry = jtcp_send_loss_probe,
};

static int jtcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    trace_tcp_v4_connect_entry(sk, uaddr, addr_len);
    jprobe_return();
    return 0;
}

static struct jprobe tcp_v4_connect_jp = {
    .kp = {
        .symbol_name = "tcp_v4_connect",
    },
    .entry = jtcp_v4_connect,
};

static int jtcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    trace_tcp_v6_connect_entry(sk, uaddr, addr_len);
    jprobe_return();
    return 0;
}

static struct jprobe tcp_v6_connect_jp = {
    .kp = {
        .symbol_name = "tcp_v6_connect",
    },
    .entry = jtcp_v6_connect,
};

static int jtcp_rcv_state_process(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th, unsigned int len)
{
    if (sk->__sk_common.skc_state != TCP_SYN_SENT)
    goto end;

    trace_tcp_rcv_state_process(sk, skb, th, len);

end:
    jprobe_return();
    return 0;
}

static struct jprobe tcp_rcv_state_process_jp = {
    .kp = {
        .symbol_name = "tcp_rcv_state_process",
    },
    .entry = jtcp_rcv_state_process,
};

static void jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
                                 const struct tcphdr *th, unsigned int len)
{
    /* TCP congestion window tracking */
    trace_tcp_probe(sk, skb);
    jprobe_return();
}

static struct jprobe tcp_rcv_established_jp = {
    .kp = {
        .symbol_name = "tcp_rcv_established",
    },
    .entry = jtcp_rcv_established,
};

static int jtcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size)
{
    trace_tcp_sendmsg(iocb, sk, msg, size);
    jprobe_return();
    return 0;
}

static struct jprobe tcp_sendmsg_jp = {
    .kp = {
        .symbol_name = "tcp_sendmsg",
    },
    .entry = jtcp_sendmsg,
};

static void jtcp_cleanup_rbuf(struct sock *sk, int copied)
{
    trace_tcp_cleanup_rbuf(sk, copied);
    jprobe_return();
}

static struct jprobe tcp_cleanup_rbuf_jp = {
    .kp = {
        .symbol_name = "tcp_cleanup_rbuf",
    },
    .entry = jtcp_cleanup_rbuf,
};

static void jtcp_set_state(struct sock *sk, int state)
{
    trace_tcp_set_state(sk, sk->sk_state, state);
    jprobe_return();
}

static struct jprobe tcp_set_state_jp = {
    .kp = {
        .symbol_name = "tcp_set_state",
    },
    .entry = jtcp_set_state,
};

static void jtcp_close(struct sock *sk, long timeout)
{
    trace_tcp_close(sk, timeout);
    jprobe_return();
}

static struct jprobe tcp_close_jp = {
    .kp = {
        .symbol_name = "tcp_close"
    },
    .entry = jtcp_close,
};

static void jtcp_destroy_sock(struct sock *sk)
{
    trace_tcp_destroy_sock(sk);
    jprobe_return();
}

static struct jprobe tcp_destroy_sock_jp = {
    .kp = {
        .symbol_name = "tcp_v4_destroy_sock",
    },
    .entry = jtcp_destroy_sock,
};

static void jtcp_rcv_space_adjust(struct sock *sk)
{
    trace_tcp_rcv_space_adjust(sk);
    jprobe_return();
}

static struct jprobe tcp_rcv_space_adjust_jp = {
    .kp = {
        .symbol_name = "tcp_rcv_space_adjust",
    },
    .entry = jtcp_rcv_space_adjust,
};

static void jtcp_receive_reset(struct sock *sk)
{
    trace_tcp_receive_reset(sk);
    jprobe_return();
}

static struct jprobe tcp_receive_reset_jp = {
    .kp = {
        .symbol_name = "tcp_reset",
    },
    .entry = jtcp_receive_reset,
};

static struct jprobe *tcp_jprobes[] = {
    &tcp_retransmit_skb_jp,
    &tcp_send_loss_probe_jp,
    &tcp_v4_connect_jp,
    &tcp_v6_connect_jp,
    &tcp_rcv_state_process_jp,
    &tcp_rcv_established_jp,
    &tcp_sendmsg_jp,
    &tcp_cleanup_rbuf_jp,
    &tcp_set_state_jp,
    &tcp_close_jp,
    &tcp_destroy_sock_jp,
    &tcp_rcv_space_adjust_jp,
    &tcp_receive_reset_jp,
};

#define TCP_CONNECT_CTX(family) struct tcp_v##family##_connect_ctx {    \
    struct sock *sk;                                                    \
    struct sockaddr *uaddr;                                             \
    int addr_len;                                                       \
};

TCP_CONNECT_CTX(4);

static int etcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v4_connect_ctx *ti = (void*)ri->data;

    ti->sk = (void*)regs->di;
    ti->uaddr = (void*)regs->si;
    ti->addr_len = (int)regs->dx;

    return 0;
}

static int rtcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v4_connect_ctx *ti = (void*)ri->data;
    struct sock *sk = ti->sk;
    struct sockaddr *uaddr = ti->uaddr;
    int addr_len = ti->addr_len;
    int retval = regs_return_value(regs);

    trace_tcp_v4_connect_return(sk, uaddr, addr_len, retval);

    return 0;
}

static struct kretprobe tcp_v4_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v4_connect",
    },
    .handler                = &rtcp_v4_connect,
    .entry_handler          = &etcp_v4_connect,
    .data_size              = sizeof(struct tcp_v4_connect_ctx),
    .maxactive              = NR_CPUS * 2,
};

TCP_CONNECT_CTX(6);

static int etcp_v6_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v6_connect_ctx *ti = (void*)ri->data;

    ti->sk = (void*)regs->di;
    ti->uaddr = (void*)regs->si;
    ti->addr_len = (int)regs->dx;

    return 0;
}

static int rtcp_v6_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v6_connect_ctx *ti = (void*)ri->data;
    struct sock *sk = ti->sk;
    struct sockaddr *uaddr = ti->uaddr;
    int addr_len = ti->addr_len;
    int retval = regs_return_value(regs);

    trace_tcp_v6_connect_return(sk, uaddr, addr_len, retval);

    return 0;
}

static struct kretprobe tcp_v6_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v6_connect",
    },
    .handler                = &rtcp_v6_connect,
    .entry_handler          = &etcp_v6_connect,
    .data_size              = sizeof(struct tcp_v6_connect_ctx),
    .maxactive              = NR_CPUS * 2,
};

static int rinet_csk_accept(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sock *sk = (void*)regs_return_value(regs);
    u8 protocol = 0;
    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk == NULL)
        return 0;

    if (sk_lingertime_offset - gso_max_segs_offset == 4)
        // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&sk->sk_gso_max_segs - 3);
    else
        // pre-4.10 with little endian
        protocol = *(u8 *)((u64)&sk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // 4.10+ with big endian
    protocol = *(u8 *)((u64)&sk->sk_gso_max_segs - 1);
    else
        // pre-4.10 with big endian
        protocol = *(u8 *)((u64)&sk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    trace_inet_csk_accept_return(sk);

    return 0;
}

static struct kretprobe inet_csk_accept_krp = {
    .kp = {
        .symbol_name = "inet_csk_accept",
    },
    .handler                = &rinet_csk_accept,
    .entry_handler          = NULL,
    .data_size              = 0,
    .maxactive              = NR_CPUS * 2,
};

struct tcp_rtx_synack_ctx {
    struct sock *sk;
    struct request_sock *req;
};

static int etcp_rtx_synack(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_rtx_synack_ctx *trsc = (void*)ri->data;

    trsc->sk = (void*)regs->di;
    trsc->req = (void*)regs->si;

    return 0;
}

static int rtcp_rtx_synack(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_rtx_synack_ctx *trsc = (void*)ri->data;

    if ((int)regs_return_value(regs)) {
       trace_tcp_retransmit_synack(trsc->sk, trsc->req);
    }

    return 0;
}

static struct kretprobe tcp_rtx_synack_krp = {
    .kp = {
        .symbol_name = "tcp_rtx_synack",
    },
    .handler                = &rtcp_rtx_synack,
    .entry_handler          = &etcp_rtx_synack,
    .data_size              = sizeof(struct tcp_rtx_synack_ctx),
    .maxactive              = NR_CPUS * 2,
};

static struct kretprobe *tcp_krps[] = {
    &tcp_v4_connect_krp,
    &tcp_v6_connect_krp,
    &inet_csk_accept_krp,
    &tcp_rtx_synack_krp,
};

static void tcp_drop(struct sock *sk, struct sk_buff *skb)
{
    if (unlikely(!skb))
        return;
    if (likely(atomic_read(&skb->users) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&skb->users)))
        return;
    //trace_tcp_drop(sk, skb);
    pr_warn("hello tcp_drop");
    __kfree_skb(skb);
}

static bool __tcp_v4_inbound_md5_hash(struct sock *sk,
                      const struct sk_buff *skb)
{
    /*
 *      * This gets called for each TCP segment that arrives
 *           * so we want to be efficient.
 *                * We have 3 drop cases:
 *                     * o No MD5 hash and one expected.
 *                          * o MD5 hash and we're not expecting one.
 *                               * o MD5 hash and its wrong.
 *                                    */
    const __u8 *hash_location = NULL;
    struct tcp_md5sig_key *hash_expected;
    const struct iphdr *iph = ip_hdr(skb);
    const struct tcphdr *th = tcp_hdr(skb);
    int genhash;
    unsigned char newhash[16];

    hash_expected = tcp_md5_do_lookup(sk, (union tcp_md5_addr *)&iph->saddr,
                      AF_INET);
    hash_location = tcp_parse_md5sig_option(th);

    /* We've parsed the options - do we have a hash? */
    if (!hash_expected && !hash_location)
        return false;

    if (hash_expected && !hash_location) {
        NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
        return true;
    }

    if (!hash_expected && hash_location) {
        NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
        return true;
    }

    /* Okay, so this is hash_expected and hash_location -
 *      * so we need to calculate the checksum.
 *           */
    genhash = tcp_v4_md5_hash_skb(newhash,
                      hash_expected,
                      NULL, NULL, skb);

    if (genhash || memcmp(hash_location, newhash, 16) != 0) {
        net_info_ratelimited("MD5 Hash failed for (%pI4, %d)->(%pI4, %d)%s\n",
                     &iph->saddr, ntohs(th->source),
                     &iph->daddr, ntohs(th->dest),
                     genhash ? " tcp_v4_calc_md5_hash failed"
                     : "");
        return true;
    }
    return false;
}

static bool tcp_v4_inbound_md5_hash(struct sock *sk, const struct sk_buff *skb)
{
    bool ret;

    rcu_read_lock();
    ret = __tcp_v4_inbound_md5_hash(sk, skb);
    rcu_read_unlock();

    return ret;
}

static int tcp_v4_md5_hash_pseudoheader(struct tcp_md5sig_pool *hp,
                    __be32 daddr, __be32 saddr, int nbytes)
{
    struct tcp4_pseudohdr *bp;
    struct scatterlist sg;

    bp = &hp->md5_blk.ip4;

    /*
 *      * 1. the TCP pseudo-header (in the order: source IP address,
 *           * destination IP address, zero-padded protocol number, and
 *                * segment length)
 *                     */
    bp->saddr = saddr;
    bp->daddr = daddr;
    bp->pad = 0;
    bp->protocol = IPPROTO_TCP;
    bp->len = cpu_to_be16(nbytes);

    sg_init_one(&sg, bp, sizeof(*bp));
    return crypto_hash_update(&hp->md5_desc, &sg, sizeof(*bp));
}

static int tcp_v4_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
                   __be32 daddr, __be32 saddr, const struct tcphdr *th)
{
    struct tcp_md5sig_pool *hp;
    struct hash_desc *desc;

    hp = tcp_get_md5sig_pool();
    if (!hp)
        goto clear_hash_noput;
    desc = &hp->md5_desc;

    if (crypto_hash_init(desc))
        goto clear_hash;
    if (tcp_v4_md5_hash_pseudoheader(hp, daddr, saddr, th->doff << 2))
        goto clear_hash;
    if (tcp_md5_hash_header(hp, th))
        goto clear_hash;
    if (tcp_md5_hash_key(hp, key))
        goto clear_hash;
    if (crypto_hash_final(desc, md5_hash))
        goto clear_hash;

    tcp_put_md5sig_pool();
    return 0;

clear_hash:
    tcp_put_md5sig_pool();
clear_hash_noput:
    memset(md5_hash, 0, 16);
    return 1;
}

static void tcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
{
    const struct tcphdr *th = tcp_hdr(skb);
    struct {
        struct tcphdr th;
#ifdef CONFIG_TCP_MD5SIG
        __be32 opt[(TCPOLEN_MD5SIG_ALIGNED >> 2)];
#endif
    } rep;
    struct ip_reply_arg arg;
#ifdef CONFIG_TCP_MD5SIG
    struct tcp_md5sig_key *key = NULL;
    const __u8 *hash_location = NULL;
    unsigned char newhash[16];
    int genhash;
    struct sock *sk1 = NULL;
#endif
    struct net *net;

    /* Never send a reset in response to a reset. */
    if (th->rst)
        return;

    /* If sk not NULL, it means we did a successful lookup and incoming
 *      * route had to be correct. prequeue might have dropped our dst.
 *           */
    if (!sk && skb_rtable(skb)->rt_type != RTN_LOCAL)
        return;

    /* Swap the send and the receive. */
    memset(&rep, 0, sizeof(rep));
    rep.th.dest   = th->source;
    rep.th.source = th->dest;
    rep.th.doff   = sizeof(struct tcphdr) / 4;
    rep.th.rst    = 1;

    if (th->ack) {
        rep.th.seq = th->ack_seq;
    } else {
        rep.th.ack = 1;
        rep.th.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
                       skb->len - (th->doff << 2));
    }

    memset(&arg, 0, sizeof(arg));
    arg.iov[0].iov_base = (unsigned char *)&rep;
    arg.iov[0].iov_len  = sizeof(rep.th);

    net = sk ? sock_net(sk) : dev_net(skb_dst(skb)->dev);
#ifdef CONFIG_TCP_MD5SIG
    hash_location = tcp_parse_md5sig_option(th);
    if (sk && sk_fullsock(sk)) {
        key = tcp_md5_do_lookup(sk, (union tcp_md5_addr *)
                    &ip_hdr(skb)->saddr, AF_INET);
    } else if (hash_location) {
        /*
 *          * active side is lost. Try to find listening socket through
 *                   * source port, and then find md5 key through listening socket.
 *                            * we are not loose security here:
 *                                     * Incoming packet is checked with md5 hash with finding key,
 *                                              * no RST generated if md5 hash doesn't match.
 *                                                       */
        sk1 = __inet_lookup_listener(net,
                         &tcp_hashinfo, ip_hdr(skb)->saddr,
                         th->source, ip_hdr(skb)->daddr,
                         ntohs(th->source), inet_iif(skb));
        /* don't send rst if it can't find key */
        if (!sk1)
            return;
        rcu_read_lock();
        key = tcp_md5_do_lookup(sk1, (union tcp_md5_addr *)
                    &ip_hdr(skb)->saddr, AF_INET);
        if (!key)
            goto release_sk1;

        genhash = tcp_v4_md5_hash_skb(newhash, key, NULL, NULL, skb);
        if (genhash || memcmp(hash_location, newhash, 16) != 0)
            goto release_sk1;
    }

    if (key) {
        rep.opt[0] = htonl((TCPOPT_NOP << 24) |
                   (TCPOPT_NOP << 16) |
                   (TCPOPT_MD5SIG << 8) |
                   TCPOLEN_MD5SIG);
        /* Update length and the length the header thinks exists */
        arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
        rep.th.doff = arg.iov[0].iov_len / 4;

        tcp_v4_md5_hash_hdr((__u8 *) &rep.opt[1],
                     key, ip_hdr(skb)->saddr,
                     ip_hdr(skb)->daddr, &rep.th);
    }
#endif
    arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
                      ip_hdr(skb)->saddr, /* XXX */
                      arg.iov[0].iov_len, IPPROTO_TCP, 0);
    arg.csumoffset = offsetof(struct tcphdr, check) / 2;
    arg.flags = (sk && inet_sk_transparent(sk)) ? IP_REPLY_ARG_NOSRCCHECK : 0;

    /* When socket is gone, all binding information is lost.
 *      * routing might fail in this case. No choice here, if we choose to force
 *           * input interface, we will misroute in case of asymmetric route.
 *                */
    if (sk)
        arg.bound_dev_if = sk->sk_bound_dev_if;

    BUILD_BUG_ON(offsetof(struct sock, sk_bound_dev_if) !=
             offsetof(struct inet_timewait_sock, tw_bound_dev_if));

    arg.tos = ip_hdr(skb)->tos;
    ip_send_unicast_reply(*this_cpu_ptr(net->ipv4_tcp_sk),
                  skb, &TCP_SKB_CB(skb)->header.h4.opt,
                  ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
                  &arg, arg.iov[0].iov_len);

    TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
    TCP_INC_STATS_BH(net, TCP_MIB_OUTRSTS);

#ifdef CONFIG_TCP_MD5SIG
release_sk1:
    if (sk1) {
        rcu_read_unlock();
        sock_put(sk1);
    }
#endif
}

static void tcp_v4_send_ack(struct sk_buff *skb, u32 seq, u32 ack,
                u32 win, u32 tsval, u32 tsecr, int oif,
                struct tcp_md5sig_key *key,
                int reply_flags, u8 tos)
{
    const struct tcphdr *th = tcp_hdr(skb);
    struct {
        struct tcphdr th;
        __be32 opt[(TCPOLEN_TSTAMP_ALIGNED >> 2)
#ifdef CONFIG_TCP_MD5SIG
               + (TCPOLEN_MD5SIG_ALIGNED >> 2)
#endif
            ];
    } rep;
    struct ip_reply_arg arg;
    struct net *net = dev_net(skb_dst(skb)->dev);

    memset(&rep.th, 0, sizeof(struct tcphdr));
    memset(&arg, 0, sizeof(arg));

    arg.iov[0].iov_base = (unsigned char *)&rep;
    arg.iov[0].iov_len  = sizeof(rep.th);
    if (tsecr) {
        rep.opt[0] = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                   (TCPOPT_TIMESTAMP << 8) |
                   TCPOLEN_TIMESTAMP);
        rep.opt[1] = htonl(tsval);
        rep.opt[2] = htonl(tsecr);
        arg.iov[0].iov_len += TCPOLEN_TSTAMP_ALIGNED;
    }

    /* Swap the send and the receive. */
    rep.th.dest    = th->source;
    rep.th.source  = th->dest;
    rep.th.doff    = arg.iov[0].iov_len / 4;
    rep.th.seq     = htonl(seq);
    rep.th.ack_seq = htonl(ack);
    rep.th.ack     = 1;
    rep.th.window  = htons(win);

#ifdef CONFIG_TCP_MD5SIG
    if (key) {
        int offset = (tsecr) ? 3 : 0;

        rep.opt[offset++] = htonl((TCPOPT_NOP << 24) |
                      (TCPOPT_NOP << 16) |
                      (TCPOPT_MD5SIG << 8) |
                      TCPOLEN_MD5SIG);
        arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
        rep.th.doff = arg.iov[0].iov_len/4;

        tcp_v4_md5_hash_hdr((__u8 *) &rep.opt[offset],
                    key, ip_hdr(skb)->saddr,
                    ip_hdr(skb)->daddr, &rep.th);
    }
#endif
    arg.flags = reply_flags;
    arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
                      ip_hdr(skb)->saddr, /* XXX */
                      arg.iov[0].iov_len, IPPROTO_TCP, 0);
    arg.csumoffset = offsetof(struct tcphdr, check) / 2;
    if (oif)
        arg.bound_dev_if = oif;
    arg.tos = tos;
    ip_send_unicast_reply(*this_cpu_ptr(net->ipv4_tcp_sk),
                  skb, &TCP_SKB_CB(skb)->header.h4.opt,
                  ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
                  &arg, arg.iov[0].iov_len);

    TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
}

static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{
    struct inet_timewait_sock *tw = inet_twsk(sk);
    struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

    tcp_v4_send_ack(skb, tcptw->tw_snd_nxt, tcptw->tw_rcv_nxt,
            tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
            tcp_time_stamp + tcptw->tw_ts_offset,
            tcptw->tw_ts_recent,
            tw->tw_bound_dev_if,
            tcp_twsk_md5_key(tcptw),
            tw->tw_transparent ? IP_REPLY_ARG_NOSRCCHECK : 0,
            tw->tw_tos
            );

    inet_twsk_put(tw);
}

static int lp_tcp_v4_rcv(struct sk_buff *skb)
{
    const struct iphdr *iph;
    const struct tcphdr *th;
    struct sock *sk;
    int ret;
    struct net *net = dev_net(skb->dev);

    if (skb->pkt_type != PACKET_HOST)
        goto discard_it;

    /* Count it even if it's bad */
    TCP_INC_STATS_BH(net, TCP_MIB_INSEGS);

    if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
        goto discard_it;

    th = tcp_hdr(skb);

    if (th->doff < sizeof(struct tcphdr) / 4)
        goto bad_packet;
    if (!pskb_may_pull(skb, th->doff * 4))
        goto discard_it;

    /* An explanation is required here, I think.
     * Packet length and doff are validated by header prediction,
     * provided case of th->doff==0 is eliminated.
     * So, we defer the checks. */

    if (skb_checksum_init(skb, IPPROTO_TCP, inet_compute_pseudo))
        goto csum_error;

    th = tcp_hdr(skb);
    iph = ip_hdr(skb);
    TCP_SKB_CB(skb)->seq = ntohl(th->seq);
    TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
                    skb->len - th->doff * 4);
    TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
    TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
    TCP_SKB_CB(skb)->tcp_tw_isn = 0;
    TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
    TCP_SKB_CB(skb)->sacked	 = 0;

    sk = __inet_lookup_skb(&tcp_hashinfo, skb, th->source, th->dest);
    if (!sk)
        goto no_tcp_socket;

process:
    if (sk->sk_state == TCP_TIME_WAIT)
        goto do_time_wait;

    if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
        NET_INC_STATS_BH(net, LINUX_MIB_TCPMINTTLDROP);
        goto discard_and_relse;
    }

    if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
        goto discard_and_relse;

#ifdef CONFIG_TCP_MD5SIG
    /*
     * We really want to reject the packet as early as possible
     * if:
     *  o We're expecting an MD5'd packet and this is no MD5 tcp option
     *  o There is an MD5 option and we're not expecting one
     */
    if (tcp_v4_inbound_md5_hash(sk, skb))
        goto discard_and_relse;
#endif

    nf_reset(skb);

    if (tcp_filter(sk, skb))
        goto discard_and_relse;
    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);

    sk_mark_napi_id(sk, skb);
    skb->dev = NULL;

    bh_lock_sock_nested(sk);
    tcp_sk(sk)->segs_in += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
    ret = 0;
    if (!sock_owned_by_user(sk)) {
        if (!tcp_prequeue(sk, skb))
            ret = tcp_v4_do_rcv(sk, skb);
    } else if (unlikely(sk_add_backlog(sk, skb,
                       sk->sk_rcvbuf + sk->sk_sndbuf))) {
        bh_unlock_sock(sk);
        NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
        goto discard_and_relse;
    }
    bh_unlock_sock(sk);

    sock_put(sk);

    return ret;

no_tcp_socket:
    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
        goto discard_it;

    if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
csum_error:
        TCP_INC_STATS_BH(net, TCP_MIB_CSUMERRORS);
bad_packet:
        TCP_INC_STATS_BH(net, TCP_MIB_INERRS);
    } else {
        tcp_v4_send_reset(NULL, skb);
    }

discard_it:
    /* Discard frame. */
    tcp_drop(sk, skb);
    // kfree_skb(skb);
    return 0;

discard_and_relse:
    sock_put(sk);
    goto discard_it;

do_time_wait:
    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
        inet_twsk_put(inet_twsk(sk));
        goto discard_it;
    }

    if (skb->len < (th->doff << 2)) {
        inet_twsk_put(inet_twsk(sk));
        goto bad_packet;
    }
    if (tcp_checksum_complete(skb)) {
        inet_twsk_put(inet_twsk(sk));
        goto csum_error;
    }
    switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
    case TCP_TW_SYN: {
        struct sock *sk2 = inet_lookup_listener(dev_net(skb->dev),
                            &tcp_hashinfo,
                            iph->saddr, th->source,
                            iph->daddr, th->dest,
                            inet_iif(skb));
        if (sk2) {
            inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
            inet_twsk_put(inet_twsk(sk));
            sk = sk2;
            goto process;
        }
        /* Fall through to ACK */
    }
    case TCP_TW_ACK:
        tcp_v4_timewait_ack(sk, skb);
        break;
    case TCP_TW_RST:
        tcp_v4_send_reset(sk, skb);
        inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
        inet_twsk_put(inet_twsk(sk));
        goto discard_it;
    case TCP_TW_SUCCESS:;
    }
    goto discard_it;
}

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

static int __init tcp_trace_init(void) {
    int ret;

    ret = register_jprobes(tcp_jprobes, sizeof(tcp_jprobes) / sizeof(tcp_jprobes[0]));
    if(ret) {
        pr_err("Register tcp jprobes failed\n");
        return ret;
    }
    pr_info("Register tcp jprobe successed\n");

    ret = register_kretprobes(tcp_krps, sizeof(tcp_krps) / sizeof(tcp_krps[0]));
    if (ret) {
        pr_err("Register tcp kretprobes failed\n");
        return ret;
    }
    pr_info("Register tcp kretprobes successed\n");

    if (!klp_have_reliable_stack() && !patch.immediate) {
        patch.immediate = true;
        pr_notice("The consistency model isn't supported for your architecture.  Bypassing safety mechanisms and applying the patch immediately.\n");
    }

    ret = klp_register_patch(&patch);
    if (ret)
        return ret;
    ret = klp_enable_patch(&patch);
    if (ret) {
        WARN_ON(klp_unregister_patch(&patch));
        return ret;
    }

    return 0;
}

static void __exit tcp_trace_exit(void) {
    unregister_jprobes(tcp_jprobes, sizeof(tcp_jprobes) / sizeof(tcp_jprobes[0]));
    pr_info("unregister tcp jprobes successed\n");
    unregister_kretprobes(tcp_krps, sizeof(tcp_krps) / sizeof(tcp_krps[0]));
    pr_info("unregister tcp kretprobes successed\n");
    WARN_ON(klp_unregister_patch(&patch));
}

MODULE_AUTHOR("Zwb <ethercflow@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
module_init(tcp_trace_init);
module_exit(tcp_trace_exit);
