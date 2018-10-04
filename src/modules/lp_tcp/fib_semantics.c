__be32 fib_info_update_nh_saddr(struct net *net, struct fib_nh *nh)
{
    nh->nh_saddr = inet_select_addr(nh->nh_dev,
                                    nh->nh_gw,
                                    nh->nh_parent->fib_scope);
    nh->nh_saddr_genid = atomic_read(&net->ipv4.dev_addr_genid);

    return nh->nh_saddr;
}
