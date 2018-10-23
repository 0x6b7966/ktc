/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 *  
 * Modified by Zwb <ethercflow@gmail.com>
 */

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
#include "lookup.h"

struct netlink_message {
	void *msg;
	struct nl_msg *nlbuf;
	int refcnt;
	LIST_ENTRY(netlink_message) ack_list_element;
	int seq;
	void (*ack_cb)(struct netlink_message *amsg, struct netlink_message *msg, int err);
};

LIST_HEAD(ack_list, netlink_message);

struct ack_list ack_list_head = {NULL};

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
	nl_join_groups(sd, 16);  // Cann't understand. do more research

	nl_connect(sd, NETLINK_GENERIC);

	return sd;

out_close:
	nl_close(sd);
	nl_socket_free(sd);
	return NULL;

}

struct netlink_message *wrap_netlink_msg(struct nlmsghdr *buf)
{
    struct netlink_message *msg;

    msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));
    if (msg) {
        msg->refcnt = 1;
        msg->msg = buf;
        msg->nlbuf = NULL;
    }

    return msg;
}

int free_netlink_msg(struct netlink_message *msg)
{
    int refcnt;

    msg->refcnt--;

    refcnt = msg->refcnt;

    if (!refcnt) {
        if (msg->nlbuf)
            nlmsg_free(msg->nlbuf);
        else
            free(msg->msg);
        free(msg);
    }

    return refcnt;
}

struct netlink_message *recv_netlink_message(int *err)
{
    static unsigned char *buf;
    struct netlink_message *msg;
    struct genlmsghdr *glm;
    struct sockaddr_nl nla;
    int type;
    int rc;

    *err = 0;

    do {
        rc = nl_recv(nsd, &nla, &buf, NULL);
        if (rc < 0) {    
            switch (errno) {
            case EINTR:
                /*
 		 * Take a pass throught the state loop
 		 */
                return NULL;
                break;
            default:
                perror("Receive operation failed:");
                return NULL;
                break;
            }
        }
    } while (rc == 0);

    msg = wrap_netlink_msg((struct nlmsghdr *)buf);

    type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

    /*
     * Note the NLMSG_ERROR is overloaded
     * Its also used to deliver ACKs
     */
    if (type == NLMSG_ERROR) {
        struct netlink_message *am;
        struct nlmsgerr *errm = nlmsg_data(msg->msg);
        LIST_FOREACH(am, &ack_list_head, ack_list_element) {
            if (am->seq == errm->msg.nlmsg_seq)
                break;
        }
    
        if (am) {    
            LIST_REMOVE(am, ack_list_element);
            am->ack_cb(msg, am, errm->error);
            free_netlink_msg(am);
        } else {
            printf("Got an unexpected ack for sequence %d\n", errm->msg.nlmsg_seq);
        }

        free_netlink_msg(msg);
        return NULL;
    }

    glm = nlmsg_data(msg->msg);
    type = glm->cmd;
    
    if ((type > TCP_DM_CMD_MAX) ||
        (type <= TCP_DM_CMD_UNSPEC)) {
        printf("Received message of unknown type %d\n", 
            type);
        free_netlink_msg(msg);
        return NULL;
    }

    return msg;    
}

void handle_dm_alert_msg(struct netlink_message *msg, int err)
{
	int i;
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct loc_result res;
	struct tcp_dm_alert_msg *alert = nla_data(genlmsg_data(glh));


	for (i=0; i < alert->entries; i++) {
		void *location;
		memcpy(&location, alert->points[i].pc, sizeof(void *));
		if (lookup_symbol(location, &res))
                        printf ("%d drops at location %p\n", alert->points[i].count, location);
                else
                        printf ("%d drops at %s+%llx (%p)\n",
                                alert->points[i].count, res.symbol, res.offset, location);
	}	

	free_netlink_msg(msg);
}

void process_rx_message(void)
{
	struct netlink_message *msg;
	int err;
	sigset_t bs;

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);
	msg = recv_netlink_message(&err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (!msg) 
		return;

	handle_dm_alert_msg(msg, err);
}

void loop(void)
{
	while (1) {
		process_rx_message();
	}
}

int main (int argc, char **argv)
{
	nsd = setup_netlink_socket();

	if (!nsd) {
		printf("Cleaning up on socket creation error\n");
		goto out;
	}

	init_lookup();

	loop();

	nl_close(nsd);
	exit(0);
out:
	exit(1);
}
