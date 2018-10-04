/*
 *	Maintain the counters used in the SNMP statistics for outgoing ICMP
 */
void icmp_out_count(struct net *net, unsigned char type)
{
    ICMPMSGOUT_INC_STATS(net, type);
    ICMP_INC_STATS(net, ICMP_MIB_OUTMSGS);
}