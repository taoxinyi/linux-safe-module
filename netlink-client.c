#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_USER 32

#define MAX_PAYLOAD 65536 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
typedef struct Message
{
    char filename[4096];
    char password[128];
    int type;

} Message;
struct Message message;
struct Message *received_message;
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Invalid args number\n");
        return -1;
    }
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(message.filename,argv[1]);
    strcpy(message.password,argv[2]);

    message.type=3;

    memcpy(NLMSG_DATA(nlh), &message, sizeof(struct Message));

    //strcpy(NLMSG_DATA(nlh), "Hello");
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    sendmsg(sock_fd, &msg, 0);
    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
    received_message=(struct Message*)NLMSG_DATA(nlh);
    close(sock_fd);
    return received_message->type;
}
