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

static struct jprobe *tcp_jprobes[] = {
    &tcp_retransmit_skb_jp,
    &tcp_send_loss_probe_jp,
    &tcp_v4_connect_jp,
    &tcp_v6_connect_jp,
    &tcp_rcv_state_process_jp
};

static int etcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    pr_warn("regs->di: %p, regs->si: %p, regs->dx: %p",
	    regs->di, regs->si, regs->dx);
    return 0;
}

static int rtcp_v4_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // struct sock *sk = (void*)regs->dx;
    // struct sockaddr *uaddr = (void*)regs->si;
    // int addr_len = (int)regs->di;

    // trace_tcp_v4_connect_return(sk, uaddr, addr_len);
    //

    pr_warn("regs->di: %p, regs->si: %p, regs->dx: %p",
	    regs->di, regs->si, regs->dx);

    return 0;
}

static struct kretprobe tcp_v4_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v4_connect",
    },
    .handler                = &rtcp_v4_connect,
    .entry_handler          = &etcp_v4_connect,
    .data_size              = 0,
    .maxactive              = NR_CPUS * 2,
};

static int rtcp_v6_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sock *sk = (void*)regs->dx;
    struct sockaddr *uaddr = (void*)regs->si;
    int addr_len = (int)regs->di;

    trace_tcp_v6_connect_return(sk, uaddr, addr_len);

    return 0;
}

static struct kretprobe tcp_v6_connect_krp = {
    .kp = {
        .symbol_name = "tcp_v6_connect",
    },
    .handler                = &rtcp_v6_connect,
    .entry_handler          = NULL,
    .data_size              = 0,
    .maxactive              = 0,
};

static struct kretprobe *tcp_krps[] = {
    &tcp_v4_connect_krp,
    &tcp_v6_connect_krp,
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
