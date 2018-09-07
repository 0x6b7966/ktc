#include <linux/module.h>
#include <net/tcp.h>

u64 sock_gen_cookie(struct sock *sk)
{
    while (1) {
        u64 res = atomic64_read(&sk->sk_cookie);

        if (res)
            return res;
        res = atomic64_inc_return(&sock_net(sk)->cookie_gen);
        atomic64_cmpxchg(&sk->sk_cookie, 0, res);
    }
}

