#include <net/xfrm.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/busy_poll.h>

#ifdef CONFIG_TCP_MD5SIG
static int tcp_v4_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
                   __be32 daddr, __be32 saddr, const struct tcphdr *th);
#endif

/*
 *	This routine will send an RST to the other tcp.
 *
 *	Someone asks: why I NEVER use socket parameters (TOS, TTL etc.)
 *		      for reset.
 *	Answer: if a packet caused RST, it is not for a socket
 *		existing in our system, if it is matched to a socket,
 *		it is just duplicate segment or bug in other side's TCP.
 *		So that we build reply only basing on parameters
 *		arrived with segment.
 *	Exception: precedence violation. We do not implement it in any case.
 */

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
     * route had to be correct. prequeue might have dropped our dst.
     */
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
         * active side is lost. Try to find listening socket through
         * source port, and then find md5 key through listening socket.
         * we are not loose security here:
         * Incoming packet is checked with md5 hash with finding key,
         * no RST generated if md5 hash doesn't match.
         */
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
     * routing might fail in this case. No choice here, if we choose to force
     * input interface, we will misroute in case of asymmetric route.
     */
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

/* The code following below sending ACKs in SYN-RECV and TIME-WAIT states
   outside socket context is ugly, certainly. What can I do?
 */

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

static int tcp_v4_md5_hash_pseudoheader(struct tcp_md5sig_pool *hp,
                                        __be32 daddr, __be32 saddr, int nbytes)
{
    struct tcp4_pseudohdr *bp;
    struct scatterlist sg;

    bp = &hp->md5_blk.ip4;

    /*
     * 1. the TCP pseudo-header (in the order: source IP address,
     * destination IP address, zero-padded protocol number, and
     * segment length)
     */
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

static bool __tcp_v4_inbound_md5_hash(struct sock *sk,
                                      const struct sk_buff *skb)
{
    /*
     * This gets called for each TCP segment that arrives
     * so we want to be efficient.
     * We have 3 drop cases:
     * o No MD5 hash and one expected.
     * o MD5 hash and we're not expecting one.
     * o MD5 hash and its wrong.
     */
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
     * so we need to calculate the checksum.
     */
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

extern int lp_tcp_v4_rcv(struct sk_buff *skb);

static void tcp_drop(struct sock *sk, struct sk_buff *skb)
{
    if (unlikely(!skb))
        return;
    if (likely(atomic_read(&skb->users) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&skb->users)))
        return;
    trace_tcp_drop(skb, __builtin_return_address(0));
    __kfree_skb(skb);
}

/*
 *	From tcp_input.c
 */

int lp_tcp_v4_rcv(struct sk_buff *skb)
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
