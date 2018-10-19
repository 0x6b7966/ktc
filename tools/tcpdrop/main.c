#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <asm/types.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "tcp_dropmon.h"

struct netlink_message {
	void *msg;
	struct nl_msg *nlbuf;
	int refcnt;
	LIST_ENTRY(netlink_message) ack_list_element;
	int seq;
	void (*ack_cb)(struct netlink_message *amsg, struct netlink_message *msg, int err);
};

static struct nl_sock *nsd;
static int nsf;

void sigint_handler(int signum)
{
	printf("Got a sigint while not receiving\n");
	return;	
}

struct nl_sock *setup_netlink_socket()
{
	struct nl_sock *sd;
	int family;

	sd = nl_socket_alloc();

	genl_connect(sd);

	family = genl_ctrl_resolve(sd, "TCP_DM");

	if (family < 0) {
		printf("Unable to find TCP_DM family, tcpdrop can't work\n");
		goto out_close;
	}

	nsf = family;

	nl_close(sd);
	nl_socket_free(sd);

	sd = nl_socket_alloc();
	nl_join_groups(sd, TCP_DM_GRP_ALERT);

	nl_connect(sd, NETLINK_GENERIC);

	return sd;

out_close:
	nl_close(sd);
	nl_socket_free(sd);
	return NULL;

}

void process_rx_message(void)
{
	struct netlink_message *msg;
	int err;
	int type;
	sigset_t bs;

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);
	msg = recv_netlink_message(&err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct genlmsghdr *glh = nlmsg_data(nlh);
		type  = glh->cmd;
		fprintf(stderr,  "type: %d\n", type);
	}
	return;
}

void loop(void)
{
	process_rx_message();
}

int main (int argc, char **argv)
{
	nsd = setup_netlink_socket();

	if (nsd == NULL) {
		printf("Cleaning up on socket creation error\n");
		goto out;
	}

	loop();

	nl_close(nsd);
	exit(0);
out:
	exit(1);
}
