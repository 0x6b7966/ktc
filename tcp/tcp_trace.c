#include <linux/module.h>
#include <linux/kprobes.h>
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
    trace_tcp_rcv_state_process(sk, skb, th, len);
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

static struct jprobe *tcp_jprobes[] = {
    &tcp_retransmit_skb_jp,
    &tcp_send_loss_probe_jp,
    &tcp_v4_connect_jp,
    &tcp_v6_connect_jp,
    &tcp_rcv_state_process_jp,
    &tcp_rcv_established_jp,
    &tcp_sendmsg_jp,
    &tcp_cleanup_rbuf_jp,
};

#define  TCP_INFO_MEMBER                        \
    struct sock *sk;                            \
    struct sockaddr *uaddr;                     \
    int addr_len;

struct tcp_v4_info {
    TCP_INFO_MEMBER
};

static int etcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v4_info *ti = (void*)ri->data;

    ti->sk = (void*)regs->di;
    ti->uaddr = (void*)regs->si;
    ti->addr_len = (int)regs->dx;

    return 0;
}

static int rtcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v4_info *ti = (void*)ri->data;
    struct sock *sk = ti->sk;
    struct sockaddr *uaddr = ti->uaddr;
    int addr_len = ti->addr_len;

    trace_tcp_v4_connect_return(sk, uaddr, addr_len);

    return 0;
}

static struct kretprobe tcp_v4_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v4_connect",
    },
    .handler                = &rtcp_v4_connect,
    .entry_handler          = &etcp_v4_connect,
    .data_size              = sizeof(struct tcp_v4_info),
    .maxactive              = NR_CPUS * 2,
};

struct tcp_v6_info {
    TCP_INFO_MEMBER
};

static int etcp_v6_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v6_info *ti = (void*)ri->data;

    ti->sk = (void*)regs->di;
    ti->uaddr = (void*)regs->si;
    ti->addr_len = (int)regs->dx;

    return 0;
}

static int rtcp_v6_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tcp_v4_info *ti = (void*)ri->data;
    struct sock *sk = ti->sk;
    struct sockaddr *uaddr = ti->uaddr;
    int addr_len = ti->addr_len;

    trace_tcp_v6_connect_return(sk, uaddr, addr_len);

    return 0;
}

static struct kretprobe tcp_v6_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v6_connect",
    },
    .handler                = &rtcp_v6_connect,
    .entry_handler          = &etcp_v6_connect,
    .data_size              = 0,
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
    .maxactive              = 0,
};

static struct kretprobe *tcp_krps[] = {
    &tcp_v4_connect_krp,
    &tcp_v6_connect_krp,
    &inet_csk_accept_krp,
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
