static int __ip_local_out_sk(struct sock *sk, struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);

    iph->tot_len = htons(skb->len);
    ip_send_check(iph);
    skb->protocol = htons(ETH_P_IP);

    return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, sk, skb, NULL,
                   skb_dst(skb)->dev, dst_output_sk);
}

int __ip_local_out(struct sk_buff *skb)
{
    return __ip_local_out_sk(skb->sk, skb);
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
    int ttl = inet->uc_ttl;

    if (ttl < 0)
        ttl = ip4_dst_hoplimit(dst);
    return ttl;
}

static inline int ip_finish_output2(struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct rtable *rt = (struct rtable *)dst;
    struct net_device *dev = dst->dev;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    u32 nexthop;

    if (rt->rt_type == RTN_MULTICAST) {
        IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTMCAST, skb->len);
    } else if (rt->rt_type == RTN_BROADCAST)
        IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTBCAST, skb->len);

    /* Be paranoid, rather than too clever. */
    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        struct sk_buff *skb2;

        skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
        if (skb2 == NULL) {
            kfree_skb(skb);
            return -ENOMEM;
        }
        if (skb->sk)
            skb_set_owner_w(skb2, skb->sk);
        consume_skb(skb);
        skb = skb2;
    }

    rcu_read_lock_bh();
    nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
    neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
    if (unlikely(!neigh))
        neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
    if (!IS_ERR(neigh)) {
        int res;

        sock_confirm_neigh(skb, neigh);
        res = dst_neigh_output(dst, neigh, skb);

        rcu_read_unlock_bh();
        return res;
    }
    rcu_read_unlock_bh();

    net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
                        __func__);
    kfree_skb(skb);
    return -EINVAL;
}

int ip_mc_output(struct sock *sk, struct sk_buff *skb)
{
    struct rtable *rt = skb_rtable(skb);
    struct net_device *dev = rt->dst.dev;

    /*
     *	If the indicated interface is up and running, send the packet.
     */
    IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    /*
     *	Multicasts are looped back for other local users
     */

    if (rt->rt_flags&RTCF_MULTICAST) {
        if (sk_mc_loop(sk)
#ifdef CONFIG_IP_MROUTE
            /* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    &&
		    ((rt->rt_flags & RTCF_LOCAL) ||
		     !(IPCB(skb)->flags & IPSKB_FORWARDED))
#endif
                ) {
            struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
            if (newskb)
                NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING,
                        sk, newskb, NULL, newskb->dev,
                        dev_loopback_xmit);
        }

        /* Multicasts with ttl 0 must not go beyond the host */

        if (ip_hdr(skb)->ttl == 0) {
            kfree_skb(skb);
            return 0;
        }
    }

    if (rt->rt_flags&RTCF_BROADCAST) {
        struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
        if (newskb)
            NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, sk, newskb,
                    NULL, newskb->dev, dev_loopback_xmit);
    }

    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, sk, skb, NULL,
                        skb->dev, ip_finish_output,
                        !(IPCB(skb)->flags & IPSKB_REROUTED));
}

int ip_output(struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb_dst(skb)->dev;

    IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, sk, skb,
                        NULL, dev,
                        ip_finish_output,
                        !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * copy saddr and daddr, possibly using 64bit load/stores
 * Equivalent to :
 *   iph->saddr = fl4->saddr;
 *   iph->daddr = fl4->daddr;
 */
static void ip_copy_addrs(struct iphdr *iph, const struct flowi4 *fl4)
{
    BUILD_BUG_ON(offsetof(typeof(*fl4), daddr) !=
    offsetof(typeof(*fl4), saddr) + sizeof(fl4->saddr));
    memcpy(&iph->saddr, &fl4->saddr,
           sizeof(fl4->saddr) + sizeof(fl4->daddr));
}

static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
    to->pkt_type = from->pkt_type;
    to->priority = from->priority;
    to->protocol = from->protocol;
    skb_dst_drop(to);
    skb_dst_copy(to, from);
    to->dev = from->dev;
    to->mark = from->mark;

    /* Copy the flags to each fragment. */
    IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
    to->tc_index = from->tc_index;
#endif
    nf_copy(to, from);
#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE)
    to->nf_trace = from->nf_trace;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
    to->ipvs_property = from->ipvs_property;
#endif
    skb_copy_secmark(to, from);
}

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
    char *kaddr;
    __wsum csum;
    kaddr = kmap(page);
    csum = csum_partial(kaddr + offset, copy, 0);
    kunmap(page);
    return csum;
}

static inline int ip_ufo_append_data(struct sock *sk,
                                     struct sk_buff_head *queue,
                                     int getfrag(void *from, char *to, int offset, int len,
                                                 int odd, struct sk_buff *skb),
                                     void *from, int length, int hh_len, int fragheaderlen,
                                     int transhdrlen, int maxfraglen, unsigned int flags)
{
    struct sk_buff *skb;
    int err;

    /* There is support for UDP fragmentation offload by network
     * device, so create one single skb packet containing complete
     * udp datagram
     */
    if ((skb = skb_peek_tail(queue)) == NULL) {
        skb = sock_alloc_send_skb(sk,
                                  hh_len + fragheaderlen + transhdrlen + 20,
                                  (flags & MSG_DONTWAIT), &err);

        if (skb == NULL)
            return err;

        /* reserve space for Hardware header */
        skb_reserve(skb, hh_len);

        /* create space for UDP/IP header */
        skb_put(skb, fragheaderlen + transhdrlen);

        /* initialize network header pointer */
        skb_reset_network_header(skb);

        /* initialize protocol header pointer */
        skb->transport_header = skb->network_header + fragheaderlen;

        skb->csum = 0;


        if (flags & MSG_CONFIRM)
            skb_set_dst_pending_confirm(skb, 1);

        __skb_queue_tail(queue, skb);
    } else if (skb_is_gso(skb)) {
        goto append;
    }

    skb->ip_summed = CHECKSUM_PARTIAL;
    /* specify the length of each IP datagram fragment */
    skb_shinfo(skb)->gso_size = maxfraglen - fragheaderlen;
    skb_shinfo(skb)->gso_type = SKB_GSO_UDP;

    append:
    return skb_append_datato_frags(sk, skb, getfrag, from,
                                   (length - transhdrlen));
}

static int __ip_append_data(struct sock *sk,
                            struct flowi4 *fl4,
                            struct sk_buff_head *queue,
                            struct inet_cork *cork,
                            struct page_frag *pfrag,
                            int getfrag(void *from, char *to, int offset,
                                        int len, int odd, struct sk_buff *skb),
                            void *from, int length, int transhdrlen,
                            unsigned int flags)
{
    struct inet_sock *inet = inet_sk(sk);
    struct sk_buff *skb;

    struct ip_options *opt = cork->opt;
    int hh_len;
    int exthdrlen;
    int mtu;
    int copy;
    int err;
    int offset = 0;
    unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
    int csummode = CHECKSUM_NONE;
    struct rtable *rt = (struct rtable *)cork->dst;

    skb = skb_peek_tail(queue);

    exthdrlen = !skb ? rt->dst.header_len : 0;
    mtu = cork->fragsize;

    hh_len = LL_RESERVED_SPACE(rt->dst.dev);

    fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
    maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
    maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

    if (cork->length + length > maxnonfragsize - fragheaderlen) {
        ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
                       mtu-exthdrlen);
        return -EMSGSIZE;
    }

    /*
     * transhdrlen > 0 means that this is the first fragment and we wish
     * it won't be fragmented in the future.
     */
    if (transhdrlen &&
        length + fragheaderlen <= mtu &&
        rt->dst.dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&
        !(flags & MSG_MORE) &&
        !exthdrlen)
        csummode = CHECKSUM_PARTIAL;

    cork->length += length;
    if ((skb && skb_is_gso(skb)) ||
        (((length + (skb ? skb->len : fragheaderlen)) > mtu) &&
         (skb_queue_len(queue) <= 1) &&
         (sk->sk_protocol == IPPROTO_UDP) &&
         (rt->dst.dev->features & NETIF_F_UFO) && !dst_xfrm(&rt->dst) &&
         (sk->sk_type == SOCK_DGRAM) && !sk->sk_no_check_tx)) {
        err = ip_ufo_append_data(sk, queue, getfrag, from, length,
                                 hh_len, fragheaderlen, transhdrlen,
                                 maxfraglen, flags);
        if (err)
            goto error;
        return 0;
    }

    /* So, what's going on in the loop below?
     *
     * We use calculated fragment length to generate chained skb,
     * each of segments is IP fragment ready for sending to network after
     * adding appropriate IP header.
     */

    if (!skb)
        goto alloc_new_skb;

    while (length > 0) {
        /* Check if the remaining data fits into current packet. */
        copy = mtu - skb->len;
        if (copy < length)
            copy = maxfraglen - skb->len;
        if (copy <= 0) {
            char *data;
            unsigned int datalen;
            unsigned int fraglen;
            unsigned int fraggap;
            unsigned int alloclen;
            struct sk_buff *skb_prev;
            alloc_new_skb:
            skb_prev = skb;
            if (skb_prev)
                fraggap = skb_prev->len - maxfraglen;
            else
                fraggap = 0;

            /*
             * If remaining data exceeds the mtu,
             * we know we need more fragment(s).
             */
            datalen = length + fraggap;
            if (datalen > mtu - fragheaderlen)
                datalen = maxfraglen - fragheaderlen;
            fraglen = datalen + fragheaderlen;

            if ((flags & MSG_MORE) &&
                !(rt->dst.dev->features&NETIF_F_SG))
                alloclen = mtu;
            else
                alloclen = fraglen;

            alloclen += exthdrlen;

            /* The last fragment gets additional space at tail.
             * Note, with MSG_MORE we overallocate on fragments,
             * because we have no idea what fragment will be
             * the last.
             */
            if (datalen == length + fraggap)
                alloclen += rt->dst.trailer_len;

            if (transhdrlen) {
                skb = sock_alloc_send_skb(sk,
                                          alloclen + hh_len + 15,
                                          (flags & MSG_DONTWAIT), &err);
            } else {
                skb = NULL;
                if (atomic_read(&sk->sk_wmem_alloc) <=
                    2 * sk->sk_sndbuf)
                    skb = sock_wmalloc(sk,
                                       alloclen + hh_len + 15, 1,
                                       sk->sk_allocation);
                if (unlikely(skb == NULL))
                    err = -ENOBUFS;
                else
                    /* only the initial fragment is
                       time stamped */
                    cork->tx_flags = 0;
            }
            if (skb == NULL)
                goto error;

            /*
             *	Fill in the control structures
             */
            skb->ip_summed = csummode;
            skb->csum = 0;
            skb_reserve(skb, hh_len);
            skb_shinfo(skb)->tx_flags = cork->tx_flags;

            /*
             *	Find where to start putting bytes.
             */
            data = skb_put(skb, fraglen + exthdrlen);
            skb_set_network_header(skb, exthdrlen);
            skb->transport_header = (skb->network_header +
                                     fragheaderlen);
            data += fragheaderlen + exthdrlen;

            if (fraggap) {
                skb->csum = skb_copy_and_csum_bits(
                        skb_prev, maxfraglen,
                        data + transhdrlen, fraggap, 0);
                skb_prev->csum = csum_sub(skb_prev->csum,
                                          skb->csum);
                data += fraggap;
                pskb_trim_unique(skb_prev, maxfraglen);
            }

            copy = datalen - transhdrlen - fraggap;
            if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
                err = -EFAULT;
                kfree_skb(skb);
                goto error;
            }

            offset += copy;
            length -= datalen - fraggap;
            transhdrlen = 0;
            exthdrlen = 0;
            csummode = CHECKSUM_NONE;

            if ((flags & MSG_CONFIRM) && !skb_prev)
                skb_set_dst_pending_confirm(skb, 1);

            /*
             * Put the packet on the pending queue.
             */
            __skb_queue_tail(queue, skb);
            continue;
        }

        if (copy > length)
            copy = length;

        if (!(rt->dst.dev->features&NETIF_F_SG)) {
            unsigned int off;

            off = skb->len;
            if (getfrag(from, skb_put(skb, copy),
                        offset, copy, off, skb) < 0) {
                __skb_trim(skb, off);
                err = -EFAULT;
                goto error;
            }
        } else {
            int i = skb_shinfo(skb)->nr_frags;

            err = -ENOMEM;
            if (!sk_page_frag_refill(sk, pfrag))
                goto error;

            if (!skb_can_coalesce(skb, i, pfrag->page,
                                  pfrag->offset)) {
                err = -EMSGSIZE;
                if (i == MAX_SKB_FRAGS)
                    goto error;

                __skb_fill_page_desc(skb, i, pfrag->page,
                                     pfrag->offset, 0);
                skb_shinfo(skb)->nr_frags = ++i;
                get_page(pfrag->page);
            }
            copy = min_t(int, copy, pfrag->size - pfrag->offset);
            if (getfrag(from,
                        page_address(pfrag->page) + pfrag->offset,
                        offset, copy, skb->len, skb) < 0)
                goto error_efault;

            pfrag->offset += copy;
            skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
            skb->len += copy;
            skb->data_len += copy;
            skb->truesize += copy;
            atomic_add(copy, &sk->sk_wmem_alloc);
        }
        offset += copy;
        length -= copy;
    }

    return 0;

    error_efault:
    err = -EFAULT;
    error:
    cork->length -= length;
    IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
    return err;
}

static int ip_setup_cork(struct sock *sk, struct inet_cork *cork,
                         struct ipcm_cookie *ipc, struct rtable **rtp)
{
    struct ip_options_rcu *opt;
    struct rtable *rt;

    /*
     * setup for corking.
     */
    opt = ipc->opt;
    if (opt) {
        if (cork->opt == NULL) {
            cork->opt = kmalloc(sizeof(struct ip_options) + 40,
                                sk->sk_allocation);
            if (unlikely(cork->opt == NULL))
                return -ENOBUFS;
        }
        memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
        cork->flags |= IPCORK_OPT;
        cork->addr = ipc->addr;
    }
    rt = *rtp;
    if (unlikely(!rt))
        return -EFAULT;
    /*
     * We steal reference to this route, caller should not release it
     */
    *rtp = NULL;
    cork->fragsize = ip_sk_use_pmtu(sk) ?
                     dst_mtu(&rt->dst) : rt->dst.dev->mtu;
    cork->dst = &rt->dst;
    cork->length = 0;
    cork->ttl = ipc->ttl;
    cork->tos = ipc->tos;
    cork->priority = ipc->priority;
    cork->tx_flags = ipc->tx_flags;

    return 0;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
int ip_append_data(struct sock *sk, struct flowi4 *fl4,
                   int getfrag(void *from, char *to, int offset, int len,
                               int odd, struct sk_buff *skb),
                   void *from, int length, int transhdrlen,
                   struct ipcm_cookie *ipc, struct rtable **rtp,
                   unsigned int flags)
{
    struct inet_sock *inet = inet_sk(sk);
    int err;

    if (flags&MSG_PROBE)
        return 0;

    if (skb_queue_empty(&sk->sk_write_queue)) {
        err = ip_setup_cork(sk, &inet->cork.base, ipc, rtp);
        if (err)
            return err;
    } else {
        transhdrlen = 0;
    }

    return __ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
                            sk_page_frag(sk), getfrag,
                            from, length, transhdrlen, flags);
}

ssize_t	ip_append_page(struct sock *sk, struct flowi4 *fl4, struct page *page,
                          int offset, size_t size, int flags)
{
    struct inet_sock *inet = inet_sk(sk);
    struct sk_buff *skb;
    struct rtable *rt;
    struct ip_options *opt = NULL;
    struct inet_cork *cork;
    int hh_len;
    int mtu;
    int len;
    int err;
    unsigned int maxfraglen, fragheaderlen, fraggap, maxnonfragsize;

    if (inet->hdrincl)
        return -EPERM;

    if (flags&MSG_PROBE)
        return 0;

    if (skb_queue_empty(&sk->sk_write_queue))
        return -EINVAL;

    cork = &inet->cork.base;
    rt = (struct rtable *)cork->dst;
    if (cork->flags & IPCORK_OPT)
        opt = cork->opt;

    if (!(rt->dst.dev->features&NETIF_F_SG))
        return -EOPNOTSUPP;

    hh_len = LL_RESERVED_SPACE(rt->dst.dev);
    mtu = cork->fragsize;

    fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
    maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
    maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

    if (cork->length + size > maxnonfragsize - fragheaderlen) {
        ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport, mtu);
        return -EMSGSIZE;
    }

    if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
        return -EINVAL;

    if ((size + skb->len > mtu) &&
        (skb_queue_len(&sk->sk_write_queue) == 1) &&
        (sk->sk_protocol == IPPROTO_UDP) &&
        (rt->dst.dev->features & NETIF_F_UFO)) {
        if (skb->ip_summed != CHECKSUM_PARTIAL)
            return -EOPNOTSUPP;

        skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
        skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
    }
    cork->length += size;


    while (size > 0) {
        if (skb_is_gso(skb)) {
            len = size;
        } else {

            /* Check if the remaining data fits into current packet. */
            len = mtu - skb->len;
            if (len < size)
                len = maxfraglen - skb->len;
        }
        if (len <= 0) {
            struct sk_buff *skb_prev;
            int alloclen;

            skb_prev = skb;
            fraggap = skb_prev->len - maxfraglen;

            alloclen = fragheaderlen + hh_len + fraggap + 15;
            skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
            if (unlikely(!skb)) {
                err = -ENOBUFS;
                goto error;
            }

            /*
             *	Fill in the control structures
             */
            skb->ip_summed = CHECKSUM_NONE;
            skb->csum = 0;
            skb_reserve(skb, hh_len);

            /*
             *	Find where to start putting bytes.
             */
            skb_put(skb, fragheaderlen + fraggap);
            skb_reset_network_header(skb);
            skb->transport_header = (skb->network_header +
                                     fragheaderlen);
            if (fraggap) {
                skb->csum = skb_copy_and_csum_bits(skb_prev,
                                                   maxfraglen,
                                                   skb_transport_header(skb),
                                                   fraggap, 0);
                skb_prev->csum = csum_sub(skb_prev->csum,
                                          skb->csum);
                pskb_trim_unique(skb_prev, maxfraglen);
            }

            /*
             * Put the packet on the pending queue.
             */
            __skb_queue_tail(&sk->sk_write_queue, skb);
            continue;
        }

        if (len > size)
            len = size;

        if (skb_append_pagefrags(skb, page, offset, len)) {
            err = -EMSGSIZE;
            goto error;
        }

        if (skb->ip_summed == CHECKSUM_NONE) {
            __wsum csum;
            csum = csum_page(page, offset, len);
            skb->csum = csum_block_add(skb->csum, csum, skb->len);
        }

        skb->len += len;
        skb->data_len += len;
        skb->truesize += len;
        atomic_add(len, &sk->sk_wmem_alloc);
        offset += len;
        size -= len;
    }
    return 0;

    error:
    cork->length -= size;
    IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
    return err;
}

static void ip_cork_release(struct inet_cork *cork)
{
    cork->flags &= ~IPCORK_OPT;
    kfree(cork->opt);
    cork->opt = NULL;
    dst_release(cork->dst);
    cork->dst = NULL;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
struct sk_buff *__ip_make_skb(struct sock *sk,
                              struct flowi4 *fl4,
                              struct sk_buff_head *queue,
                              struct inet_cork *cork)
{
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ip_options *opt = NULL;
    struct rtable *rt = (struct rtable *)cork->dst;
    struct iphdr *iph;
    __be16 df = 0;
    __u8 ttl;

    if ((skb = __skb_dequeue(queue)) == NULL)
        goto out;
    tail_skb = &(skb_shinfo(skb)->frag_list);

    /* move skb->data to ip header from ext header */
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }

    /* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
     * to fragment the frame generated here. No matter, what transforms
     * how transforms change size of the packet, it will come out.
     */
    skb->ignore_df = ip_sk_ignore_df(sk);

    /* DF bit is set when we want to see DF on outgoing frames.
     * If ignore_df is set too, we still allow to fragment this frame
     * locally. */
    if (inet->pmtudisc == IP_PMTUDISC_DO ||
        inet->pmtudisc == IP_PMTUDISC_PROBE ||
        (skb->len <= dst_mtu(&rt->dst) &&
         ip_dont_fragment(sk, &rt->dst)))
        df = htons(IP_DF);

    if (cork->flags & IPCORK_OPT)
        opt = cork->opt;

    if (cork->ttl != 0)
        ttl = cork->ttl;
    else if (rt->rt_type == RTN_MULTICAST)
        ttl = inet->mc_ttl;
    else
        ttl = ip_select_ttl(inet, &rt->dst);

    iph = ip_hdr(skb);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
    iph->frag_off = df;
    iph->ttl = ttl;
    iph->protocol = sk->sk_protocol;
    ip_copy_addrs(iph, fl4);
    ip_select_ident(net, skb, sk);

    if (opt) {
        iph->ihl += opt->optlen>>2;
        ip_options_build(skb, opt, cork->addr, rt, 0);
    }

    skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
    skb->mark = sk->sk_mark;
    /*
     * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
     * on dst refcount
     */
    cork->dst = NULL;
    skb_dst_set(skb, &rt->dst);

    if (iph->protocol == IPPROTO_ICMP)
        icmp_out_count(net, ((struct icmphdr *)
                skb_transport_header(skb))->type);

    ip_cork_release(cork);
    out:
    return skb;
}

int ip_send_skb(struct net *net, struct sk_buff *skb)
{
    int err;

    err = ip_local_out(skb);
    if (err) {
        if (err > 0)
            err = net_xmit_errno(err);
        if (err)
            IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
    }

    return err;
}

int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4)
{
    struct sk_buff *skb;

    skb = ip_finish_skb(sk, fl4);
    if (!skb)
        return 0;

    /* Netfilter gets whole the not fragmented skb. */
    return ip_send_skb(sock_net(sk), skb);
}

/*
 *	Throw away all pending data on the socket.
 */
static void __ip_flush_pending_frames(struct sock *sk,
                                      struct sk_buff_head *queue,
                                      struct inet_cork *cork)
{
    struct sk_buff *skb;

    while ((skb = __skb_dequeue_tail(queue)) != NULL)
        kfree_skb(skb);

    ip_cork_release(cork);
}

void ip_flush_pending_frames(struct sock *sk)
{
    __ip_flush_pending_frames(sk, &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}

struct sk_buff *ip_make_skb(struct sock *sk,
                            struct flowi4 *fl4,
                            int getfrag(void *from, char *to, int offset,
                                        int len, int odd, struct sk_buff *skb),
                            void *from, int length, int transhdrlen,
                            struct ipcm_cookie *ipc, struct rtable **rtp,
                            unsigned int flags)
{
    struct inet_cork cork;
    struct sk_buff_head queue;
    int err;

    if (flags & MSG_PROBE)
        return NULL;

    __skb_queue_head_init(&queue);

    cork.flags = 0;
    cork.addr = 0;
    cork.opt = NULL;
    err = ip_setup_cork(sk, &cork, ipc, rtp);
    if (err)
        return ERR_PTR(err);

    err = __ip_append_data(sk, fl4, &queue, &cork,
                           &current->task_frag, getfrag,
                           from, length, transhdrlen, flags);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, &cork);
        return ERR_PTR(err);
    }

    return __ip_make_skb(sk, fl4, &queue, &cork);
}

/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
                              int len, int odd, struct sk_buff *skb)
{
    __wsum csum;

    csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
    skb->csum = csum_block_add(skb->csum, csum, odd);
    return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send some TCP resets/acks so far.
 */
void ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb,
                           const struct ip_options *sopt,
                           __be32 daddr, __be32 saddr,
                           const struct ip_reply_arg *arg,
                           unsigned int len)
{
    struct ip_options_data replyopts;
    struct ipcm_cookie ipc;
    struct flowi4 fl4;
    struct rtable *rt = skb_rtable(skb);
    struct net *net = sock_net(sk);
    struct sk_buff *nskb;
    int err;

    if (__ip_options_echo(&replyopts.opt.opt, skb, sopt))
        return;

    ipc.addr = daddr;
    ipc.opt = NULL;
    ipc.tx_flags = 0;
    ipc.ttl = 0;
    ipc.tos = -1;

    if (replyopts.opt.opt.optlen) {
        ipc.opt = &replyopts.opt;

        if (replyopts.opt.opt.srr)
            daddr = replyopts.opt.opt.faddr;
    }

    flowi4_init_output(&fl4, arg->bound_dev_if,
                       IP4_REPLY_MARK(net, skb->mark),
                       RT_TOS(arg->tos),
                       RT_SCOPE_UNIVERSE, ip_hdr(skb)->protocol,
                       ip_reply_arg_flowi_flags(arg),
                       daddr, saddr,
                       tcp_hdr(skb)->source, tcp_hdr(skb)->dest);
    security_skb_classify_flow(skb, flowi4_to_flowi(&fl4));
    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
        return;

    inet_sk(sk)->tos = arg->tos;

    sk->sk_priority = skb->priority;
    sk->sk_protocol = ip_hdr(skb)->protocol;
    sk->sk_bound_dev_if = arg->bound_dev_if;
    sk->sk_sndbuf = sysctl_wmem_default;
    sk->sk_mark = fl4.flowi4_mark;
    err = ip_append_data(sk, &fl4, ip_reply_glue_bits, arg->iov->iov_base,
                         len, 0, &ipc, &rt, MSG_DONTWAIT);
    if (unlikely(err)) {
        ip_flush_pending_frames(sk);
        goto out;
    }

    nskb = skb_peek(&sk->sk_write_queue);
    if (nskb) {
        if (arg->csumoffset >= 0)
            *((__sum16 *)skb_transport_header(nskb) +
              arg->csumoffset) = csum_fold(csum_add(nskb->csum,
                                                    arg->csum));
        nskb->ip_summed = CHECKSUM_NONE;
        skb_set_queue_mapping(nskb, skb_get_queue_mapping(skb));
        ip_push_pending_frames(sk, &fl4);
    }
    out:
    ip_rt_put(rt);
}

void __init ip_init(void)
{
    ip_rt_init();
    inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
    igmp_mc_proc_init();
#endif
}
