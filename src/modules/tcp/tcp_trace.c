#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/tcp.h>

#define CREATE_TRACE_POINTS
#include "tcp_trace.h"

#define _DECL_CMN_JRP(fn, symbol) static struct jprobe fn##_jp = { \
    .entry	        = on_##fn##_ent,                           \
    .kp.symbol_name = ""#symbol"",                                 \
};

#define DECL_CMN_JRP(fn) _DECL_CMN_JRP(fn, fn)

static int on_tcp_retransmit_skb_ent(struct sock *sk, struct sk_buff *skb)
{
    trace_tcp_retransmit_skb(sk, skb);
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_retransmit_skb);

static int on_tcp_send_loss_probe_ent(struct sock *sk)
{
    trace_tcp_send_loss_probe(sk);
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_send_loss_probe);

static int on_tcp_v4_connect_ent(struct sock *sk, struct sockaddr *uaddr,
                                 int addr_len)
{
    trace_tcp_v4_connect_entry(sk, uaddr, addr_len);
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_v4_connect);

static int on_tcp_v6_connect_ent(struct sock *sk, struct sockaddr *uaddr,
                                 int addr_len)
{
    trace_tcp_v6_connect_entry(sk, uaddr, addr_len);
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_v6_connect);

static int on_tcp_rcv_state_process_ent(struct sock *sk, struct sk_buff *skb,
                                        const struct tcphdr *th, unsigned int len)
{
    if (sk->__sk_common.skc_state != TCP_SYN_SENT)
        goto end;

    trace_tcp_rcv_state_process(sk, skb, th, len);

end:
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_rcv_state_process);

static void on_tcp_rcv_established_ent(struct sock *sk, struct sk_buff *skb,
                                       const struct tcphdr *th, unsigned int len)
{
    /* TCP congestion window tracking */
    trace_tcp_probe(sk, skb);
    jprobe_return();
}

DECL_CMN_JRP(tcp_rcv_established);

static int on_tcp_sendmsg_ent(struct kiocb *iocb, struct sock *sk,
                              struct msghdr *msg, size_t size)
{
    trace_tcp_sendmsg(iocb, sk, msg, size);
    jprobe_return();
    return 0;
}

DECL_CMN_JRP(tcp_sendmsg);

static void on_tcp_cleanup_rbuf_ent(struct sock *sk, int copied)
{
    trace_tcp_cleanup_rbuf(sk, copied);
    jprobe_return();
}

DECL_CMN_JRP(tcp_cleanup_rbuf);

static void on_tcp_set_state_ent(struct sock *sk, int state)
{
    trace_tcp_set_state(sk, sk->sk_state, state);
    jprobe_return();
}

DECL_CMN_JRP(tcp_set_state);

static void on_tcp_close_ent(struct sock *sk, long timeout)
{
    trace_tcp_close(sk, timeout);
    jprobe_return();
}

DECL_CMN_JRP(tcp_close);

static void on_tcp_v4_destroy_sock_ent(struct sock *sk)
{
    trace_tcp_destroy_sock(sk);
    jprobe_return();
}

DECL_CMN_JRP(tcp_v4_destroy_sock);

static void on_tcp_rcv_space_adjust_ent(struct sock *sk)
{
    trace_tcp_rcv_space_adjust(sk);
    jprobe_return();
}

DECL_CMN_JRP(tcp_rcv_space_adjust);

/*
 * tcp_receive_reset
 */
static void on_tcp_reset_ent(struct sock *sk)
{
    trace_tcp_receive_reset(sk);
    jprobe_return();
}

DECL_CMN_JRP(tcp_reset);

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
    &tcp_v4_destroy_sock_jp,
    &tcp_rcv_space_adjust_jp,
    &tcp_reset_jp,
};

#define _DECL_CMN_KRP(fn, symbol) static struct kretprobe fn##_krp = { \
    .entry_handler	= on_krp_##fn##_ent,                           \
    .handler		= on_krp_##fn##_ret,                           \
    .data_size		= sizeof(fn##_args),                           \
    .maxactive		= NR_CPUS * 2,                                 \
    .kp.symbol_name = ""#symbol"",                                     \
};

#define DECL_CMN_KRP(fn) _DECL_CMN_KRP(fn, fn)

#define TCP_CONNECT_CTX(family) struct tcp_v##family##_connect_ctx { \
    struct sock *sk;                                                 \
    struct sockaddr *uaddr;                                          \
    int addr_len;                                                    \
};

TCP_CONNECT_CTX(4);
TCP_CONNECT_CTX(6);

#undef TCP_CONNECT_CTX
#define TCP_CONNECT_CTX(family) struct tcp_v##family##_connect_ctx

#define DECL_CONNECT_KRP(fn, family) \
static int on_krp_##fn##_ent(struct kretprobe_instance *ri, struct pt_regs *regs) \
{                                                                                 \
    TCP_CONNECT_CTX(family) *ti = (void*)ri->data;                                \
    ti->sk = (void*)regs->di;                                                     \
    ti->uaddr = (void*)regs->si;                                                  \
    ti->addr_len = (int)regs->dx;                                                 \
    return 0;                                                                     \
}                                                                                 \
static int on_krp_##fn##_ret(struct kretprobe_instance *ri, struct pt_regs *regs) \
{                                                                                 \
    TCP_CONNECT_CTX(family) *ti = (void*)ri->data;                                \
    struct sock *sk = ti->sk;                                                     \
    struct sockaddr *uaddr = ti->uaddr;                                           \
    int addr_len = ti->addr_len;                                                  \
    int retval = regs_return_value(regs);                                         \
    trace_tcp_v4_connect_return(sk, uaddr, addr_len, retval);                     \
    return 0;                                                                     \
}                                                                                 \
static struct kretprobe fn##_krp = {                                              \
    .entry_handler	= on_krp_##fn##_ent,                                      \
    .handler		= on_krp_##fn##_ret,                                      \
    .data_size		= sizeof(TCP_CONNECT_CTX(family)),                        \
    .maxactive		= NR_CPUS * 2,                                            \
    .kp.symbol_name = ""#fn"",                                                    \
};

DECL_CONNECT_KRP(tcp_v4_connect, 4);
DECL_CONNECT_KRP(tcp_v6_connect, 6);

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

    return 0;
}

static void __exit tcp_trace_exit(void) {
    unregister_jprobes(tcp_jprobes, sizeof(tcp_jprobes) / sizeof(tcp_jprobes[0]));
    pr_info("unregister tcp jprobes successed\n");
    unregister_kretprobes(tcp_krps, sizeof(tcp_krps) / sizeof(tcp_krps[0]));
    pr_info("unregister tcp kretprobes successed\n");
}

MODULE_AUTHOR("Zwb <ethercflow@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
module_init(tcp_trace_init);
module_exit(tcp_trace_exit);
