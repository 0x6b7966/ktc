#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/livepatch.h>
#include <net/tcp.h>

#define CREATE_TRACE_POINTS
#include "tcp_trace.h"

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

void tcp_drop(struct sock *sk, struct sk_buff *skb)
{
    if (unlikely(!skb))
        return;
    if (likely(atomic_read(&skb->users) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&skb->users)))
        return;
    trace_tcp_drop(sk, skb);
    __kfree_skb(skb);
}
EXPORT_SYMBOL(tcp_drop);

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
    tcp_drop(sk, skb)
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
        .new_func = "lp_tcp_v4_rcv",
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
