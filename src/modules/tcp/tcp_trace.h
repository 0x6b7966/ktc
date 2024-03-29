#undef TRACE_SYSTEM
#define TRACE_SYSTEM tcp

#if !defined(_TRACE_TCP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TCP_H

#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/tracepoint.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/sock_diag.h>

#define TP_STORE_V4MAPPED(__entry, saddr, daddr)		\
    do {							\
        struct in6_addr *pin6;				\
                                \
        pin6 = (struct in6_addr *)__entry->saddr_v6;	\
        ipv6_addr_set_v4mapped(saddr, pin6);		\
        pin6 = (struct in6_addr *)__entry->daddr_v6;	\
        ipv6_addr_set_v4mapped(daddr, pin6);		\
    } while (0)

#if IS_ENABLED(CONFIG_IPV6)
#define TP_STORE_ADDRS(__entry, saddr, daddr, saddr6, daddr6)		\
    do {								\
        if (sk->sk_family == AF_INET6) {			\
            struct in6_addr *pin6;				\
                                    \
            pin6 = (struct in6_addr *)__entry->saddr_v6;	\
            *pin6 = saddr6;					\
            pin6 = (struct in6_addr *)__entry->daddr_v6;	\
            *pin6 = daddr6;					\
        } else {						\
            TP_STORE_V4MAPPED(__entry, saddr, daddr);	\
        }							\
    } while (0)
#else
#define TP_STORE_ADDRS(__entry, saddr, daddr, saddr6, daddr6)	\
    TP_STORE_V4MAPPED(__entry, saddr, daddr)
#endif

/*
 * tcp event with arguments sk and skb
 *
 * Note: this class requires a valid sk pointer; while skb pointer could
 *       be NULL.
 */
DECLARE_EVENT_CLASS(tcp_event_sk_skb,

    TP_PROTO(const struct sock *sk, const struct sk_buff *skb),

    TP_ARGS(sk, skb),

    TP_STRUCT__entry(
        __field(const void *, skbaddr)
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(int, state)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skbaddr = skb;
        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                  sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->state = sk->sk_state;

    ),

    TP_printk("sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c, state=%d",
          __entry->sport, __entry->dport, __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6, __entry->state)
);

DEFINE_EVENT(tcp_event_sk_skb, tcp_retransmit_skb,

    TP_PROTO(const struct sock *sk, const struct sk_buff *skb),

    TP_ARGS(sk, skb)
);

/*
 * tcp event with arguments sk
 *
 * Note: this class requires a valid sk pointer.
 */
DECLARE_EVENT_CLASS(tcp_event_sk,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(int, state)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);
    ),

    TP_printk("sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c, state=%d",
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->state)
);

DEFINE_EVENT(tcp_event_sk, tcp_send_loss_probe,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk)
);

DEFINE_EVENT(tcp_event_sk, inet_csk_accept_return,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk)
);

DEFINE_EVENT(tcp_event_sk, tcp_destroy_sock,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk)
);

DEFINE_EVENT(tcp_event_sk, tcp_rcv_space_adjust,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk)
);

DEFINE_EVENT(tcp_event_sk, tcp_receive_reset,

    TP_PROTO(struct sock *sk),

    TP_ARGS(sk)
);

DECLARE_EVENT_CLASS(tcp_event_conn_entry,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len),

    TP_ARGS(sk, uaddr, addr_len),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
    ),

    TP_fast_assign(
        __entry->skaddr = sk;
    ),

    TP_printk("skaddr=%p", __entry->skaddr)
);

DEFINE_EVENT(tcp_event_conn_entry, tcp_v4_connect_entry,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len),

    TP_ARGS(sk, uaddr, addr_len)
);

DEFINE_EVENT(tcp_event_conn_entry, tcp_v6_connect_entry,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len),

    TP_ARGS(sk, uaddr, addr_len)
);

DECLARE_EVENT_CLASS(tcp_event_conn_return,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len, int retval),

    TP_ARGS(sk, uaddr, addr_len, retval),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(int, retval)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->retval = retval;
    ),

    TP_printk("skaddr=%p sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c, retval=%d",
          __entry->skaddr,
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->retval)
);

DEFINE_EVENT(tcp_event_conn_return, tcp_v4_connect_return,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len, int retval),

    TP_ARGS(sk, uaddr, addr_len, retval)
);

DEFINE_EVENT(tcp_event_conn_return, tcp_v6_connect_return,

    TP_PROTO(struct sock *sk, struct sockaddr *uaddr, int addr_len, int retval),

    TP_ARGS(sk, uaddr, addr_len, retval)
);

TRACE_EVENT(tcp_rcv_state_process,

    TP_PROTO(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th, unsigned int len),

    TP_ARGS(sk, skb, th, len),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);
    ),

    TP_printk("skaddr=%p sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c",
          __entry->skaddr,
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6)
);

TRACE_EVENT(tcp_sendmsg,

    TP_PROTO(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size),

    TP_ARGS(iocb, sk, msg, size),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(__u64, size)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->size = size;
    ),

    TP_printk("sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c size=%llu",
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->size)
);

TRACE_EVENT(tcp_cleanup_rbuf,

    TP_PROTO(struct sock *sk, int copied),

    TP_ARGS(sk, copied),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(__u64, copied)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->copied = copied;
    ),

    TP_printk("sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c copied=%llu",
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->copied)
);

TRACE_EVENT(tcp_set_state,

    TP_PROTO(const struct sock *sk, const int oldstate, const int newstate),

    TP_ARGS(sk, oldstate, newstate),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(int, oldstate)
        __field(int, newstate)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(__u64, rx_b)
        __field(__u64, tx_b)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        struct tcp_sock *tp = tcp_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;
        __entry->oldstate = oldstate;
        __entry->newstate = newstate;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->rx_b = tp->bytes_received;
        __entry->tx_b = tp->bytes_acked;

    ),

    TP_printk("skaddr=%p sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c oldstate=%d newstate=%d rx_b=%llu tx_b=%llu",
          __entry->skaddr,
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->oldstate,
          __entry->newstate,
          __entry->rx_b,
          __entry->tx_b)
);

TRACE_EVENT(tcp_close,

    TP_PROTO(const struct sock *sk, long timeout),

    TP_ARGS(sk, timeout),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
        __field(int, oldstate)
    ),

    TP_fast_assign(
        struct inet_sock *inet = inet_sk(sk);
        __be32 *p32;

        __entry->skaddr = sk;

        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);

        p32 = (__be32 *) __entry->saddr;
        *p32 = inet->inet_saddr;

        p32 = (__be32 *) __entry->daddr;
        *p32 =  inet->inet_daddr;

        TP_STORE_ADDRS(__entry, inet->inet_saddr, inet->inet_daddr,
                   sk->sk_v6_rcv_saddr, sk->sk_v6_daddr);

        __entry->oldstate = sk->sk_state;
    ),

    TP_printk("skaddr=%p sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c, oldstate=%d",
          __entry->skaddr,
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6,
          __entry->oldstate)
);

TRACE_EVENT(tcp_retransmit_synack,

    TP_PROTO(const struct sock *sk, const struct request_sock *req),

    TP_ARGS(sk, req),

    TP_STRUCT__entry(
        __field(const void *, skaddr)
        __field(const void *, req)
        __field(__u16, sport)
        __field(__u16, dport)
        __array(__u8, saddr, 4)
        __array(__u8, daddr, 4)
        __array(__u8, saddr_v6, 16)
        __array(__u8, daddr_v6, 16)
    ),

    TP_fast_assign(
        struct inet_request_sock *ireq = inet_rsk(req);
        __be32 *p32;

        __entry->skaddr = sk;
        __entry->req = req;

        __entry->sport = ireq->ir_num;
        __entry->dport = ntohs(ireq->ir_rmt_port);

        p32 = (__be32 *) __entry->saddr;
        *p32 = ireq->ir_loc_addr;

        p32 = (__be32 *) __entry->daddr;
        *p32 = ireq->ir_rmt_addr;

        TP_STORE_ADDRS(__entry, ireq->ir_loc_addr, ireq->ir_rmt_addr,
                  ireq->ir_v6_loc_addr, ireq->ir_v6_rmt_addr);
    ),

    TP_printk("sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c",
          __entry->sport, __entry->dport,
          __entry->saddr, __entry->daddr,
          __entry->saddr_v6, __entry->daddr_v6)
);

#include "net_probe_common.h"

TRACE_EVENT(tcp_probe,

    TP_PROTO(struct sock *sk, struct sk_buff *skb),

    TP_ARGS(sk, skb),

    TP_STRUCT__entry(
        /* sockaddr_in6 is always bigger than sockaddr_in */
        __array(__u8, saddr, sizeof(struct sockaddr_in6))
        __array(__u8, daddr, sizeof(struct sockaddr_in6))
        __field(__u16, sport)
        __field(__u16, dport)
        __field(__u32, mark)
        __field(__u16, data_len)
        __field(__u32, snd_nxt)
        __field(__u32, snd_una)
        __field(__u32, snd_cwnd)
        __field(__u32, ssthresh)
        __field(__u32, snd_wnd)
        __field(__u32, srtt)
        __field(__u32, rcv_wnd)
    ),

    TP_fast_assign(
        const struct tcphdr *th = (const struct tcphdr *)skb->data;
        const struct inet_sock *inet = inet_sk(sk);
        const struct tcp_sock *tp = tcp_sk(sk);

        memset(__entry->saddr, 0, sizeof(struct sockaddr_in6));
        memset(__entry->daddr, 0, sizeof(struct sockaddr_in6));

        TP_STORE_ADDR_PORTS(__entry, inet, sk);

        /* For filtering use */
        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);
        __entry->mark = skb->mark;

        __entry->data_len = skb->len - __tcp_hdrlen(th);
        __entry->snd_nxt = tp->snd_nxt;
        __entry->snd_una = tp->snd_una;
        __entry->snd_cwnd = tp->snd_cwnd;
        __entry->snd_wnd = tp->snd_wnd;
        __entry->rcv_wnd = tp->rcv_wnd;
        __entry->ssthresh = tcp_current_ssthresh(sk);
        __entry->srtt = tp->srtt_us >> 3;
    ),

    TP_printk("src=%pISpc dest=%pISpc mark=%#x data_len=%d snd_nxt=%#x snd_una=%#x snd_cwnd=%u ssthresh=%u snd_wnd=%u srtt=%u rcv_wnd=%u",
          __entry->saddr, __entry->daddr, __entry->mark,
          __entry->data_len, __entry->snd_nxt, __entry->snd_una,
          __entry->snd_cwnd, __entry->ssthresh, __entry->snd_wnd,
          __entry->srtt, __entry->rcv_wnd)
);

TRACE_EVENT(tcp_drop,

    TP_PROTO(struct sock *sk, struct sk_buff *skb),

    TP_ARGS(sk, skb),

    TP_STRUCT__entry(
        /* sockaddr_in6 is always bigger than sockaddr_in */
        __array(__u8, saddr, sizeof(struct sockaddr_in6))
        __array(__u8, daddr, sizeof(struct sockaddr_in6))
        __field(__u16, sport)
        __field(__u16, dport)
        __field(__u32, mark)
        __field(__u16, data_len)
        __field(__u32, snd_nxt)
        __field(__u32, snd_una)
        __field(__u32, snd_cwnd)
        __field(__u32, ssthresh)
        __field(__u32, snd_wnd)
        __field(__u32, srtt)
        __field(__u32, rcv_wnd)
    ),

    TP_fast_assign(
        const struct tcphdr *th = (const struct tcphdr *)skb->data;
        const struct inet_sock *inet = inet_sk(sk);
        const struct tcp_sock *tp = tcp_sk(sk);

        memset(__entry->saddr, 0, sizeof(struct sockaddr_in6));
        memset(__entry->daddr, 0, sizeof(struct sockaddr_in6));

        TP_STORE_ADDR_PORTS(__entry, inet, sk);

        /* For filtering use */
        __entry->sport = ntohs(inet->inet_sport);
        __entry->dport = ntohs(inet->inet_dport);
        __entry->mark = skb->mark;

        __entry->data_len = skb->len - __tcp_hdrlen(th);
        __entry->snd_nxt = tp->snd_nxt;
        __entry->snd_una = tp->snd_una;
        __entry->snd_cwnd = tp->snd_cwnd;
        __entry->snd_wnd = tp->snd_wnd;
        __entry->rcv_wnd = tp->rcv_wnd;
        __entry->ssthresh = tcp_current_ssthresh(sk);
        __entry->srtt = tp->srtt_us >> 3;
    ),

    TP_printk("src=%pISpc dest=%pISpc mark=%#x data_len=%d snd_nxt=%#x snd_una=%#x snd_cwnd=%u ssthresh=%u snd_wnd=%u srtt=%u rcv_wnd=%u",
          __entry->saddr, __entry->daddr, __entry->mark,
          __entry->data_len, __entry->snd_nxt, __entry->snd_una,
          __entry->snd_cwnd, __entry->ssthresh, __entry->snd_wnd,
          __entry->srtt, __entry->rcv_wnd)
);

#endif /* _TRACE_TCP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tcp_trace
#include <trace/define_trace.h>
