#include <net/ip.h>
#include <net/tcp.h>
#include <net/ip_fib.h>

/*
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */

void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
                      __be32 daddr, struct rtable *rt, int is_frag)
{
    unsigned char *iph = skb_network_header(skb);

    memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
    memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
    opt = &(IPCB(skb)->opt);

    if (opt->srr)
        memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

    if (!is_frag) {
        if (opt->rr_needaddr)
            ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, skb, rt);
        if (opt->ts_needaddr)
            ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, skb, rt);
        if (opt->ts_needtime) {
            struct timespec tv;
            __be32 midtime;
            getnstimeofday(&tv);
            midtime = htonl((tv.tv_sec % 86400) * MSEC_PER_SEC + tv.tv_nsec / NSEC_PER_MSEC);
            memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
        }
        return;
    }
    if (opt->rr) {
        memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
        opt->rr = 0;
        opt->rr_needaddr = 0;
    }
    if (opt->ts) {
        memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
        opt->ts = 0;
        opt->ts_needaddr = opt->ts_needtime = 0;
    }
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int __ip_options_echo(struct ip_options *dopt, struct sk_buff *skb,
                      const struct ip_options *sopt)
{
    unsigned char *sptr, *dptr;
    int soffset, doffset;
    int	optlen;

    memset(dopt, 0, sizeof(struct ip_options));

    if (sopt->optlen == 0)
        return 0;

    sptr = skb_network_header(skb);
    dptr = dopt->__data;

    if (sopt->rr) {
        optlen  = sptr[sopt->rr+1];
        soffset = sptr[sopt->rr+2];
        dopt->rr = dopt->optlen + sizeof(struct iphdr);
        memcpy(dptr, sptr+sopt->rr, optlen);
        if (sopt->rr_needaddr && soffset <= optlen) {
            if (soffset + 3 > optlen)
                return -EINVAL;
            dptr[2] = soffset + 4;
            dopt->rr_needaddr = 1;
        }
        dptr += optlen;
        dopt->optlen += optlen;
    }
    if (sopt->ts) {
        optlen = sptr[sopt->ts+1];
        soffset = sptr[sopt->ts+2];
        dopt->ts = dopt->optlen + sizeof(struct iphdr);
        memcpy(dptr, sptr+sopt->ts, optlen);
        if (soffset <= optlen) {
            if (sopt->ts_needaddr) {
                if (soffset + 3 > optlen)
                    return -EINVAL;
                dopt->ts_needaddr = 1;
                soffset += 4;
            }
            if (sopt->ts_needtime) {
                if (soffset + 3 > optlen)
                    return -EINVAL;
                if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
                    dopt->ts_needtime = 1;
                    soffset += 4;
                } else {
                    dopt->ts_needtime = 0;

                    if (soffset + 7 <= optlen) {
                        __be32 addr;

                        memcpy(&addr, dptr+soffset-1, 4);
                        if (inet_addr_type(dev_net(skb_dst(skb)->dev), addr) != RTN_UNICAST) {
                            dopt->ts_needtime = 1;
                            soffset += 8;
                        }
                    }
                }
            }
            dptr[2] = soffset;
        }
        dptr += optlen;
        dopt->optlen += optlen;
    }
    if (sopt->srr) {
        unsigned char *start = sptr+sopt->srr;
        __be32 faddr;

        optlen  = start[1];
        soffset = start[2];
        doffset = 0;
        if (soffset > optlen)
            soffset = optlen + 1;
        soffset -= 4;
        if (soffset > 3) {
            memcpy(&faddr, &start[soffset-1], 4);
            for (soffset-=4, doffset=4; soffset > 3; soffset-=4, doffset+=4)
                memcpy(&dptr[doffset-1], &start[soffset-1], 4);
            /*
             * RFC1812 requires to fix illegal source routes.
             */
            if (memcmp(&ip_hdr(skb)->saddr,
                       &start[soffset + 3], 4) == 0)
                doffset -= 4;
        }
        if (doffset > 3) {
            __be32 daddr = fib_compute_spec_dst(skb);

            memcpy(&start[doffset-1], &daddr, 4);
            dopt->faddr = faddr;
            dptr[0] = start[0];
            dptr[1] = doffset+3;
            dptr[2] = 4;
            dptr += doffset+3;
            dopt->srr = dopt->optlen + sizeof(struct iphdr);
            dopt->optlen += doffset+3;
            dopt->is_strictroute = sopt->is_strictroute;
        }
    }
    if (sopt->cipso) {
        optlen  = sptr[sopt->cipso+1];
        dopt->cipso = dopt->optlen+sizeof(struct iphdr);
        memcpy(dptr, sptr+sopt->cipso, optlen);
        dptr += optlen;
        dopt->optlen += optlen;
    }
    while (dopt->optlen & 3) {
        *dptr++ = IPOPT_END;
        dopt->optlen++;
    }
    return 0;
}