/* Linux kernel net/ipv4/tcp_input.c simulation */
#include <stdlib.h>

struct tcp_sock {
    unsigned int rcv_nxt;
    unsigned int copied_seq;
    void *rcv_queue;
};

/* CVE-like: Integer overflow in TCP handling */
int tcp_data_queue(struct tcp_sock *tp, unsigned int seq, unsigned int len)
{
    /* VULNERABILITY: Integer overflow */
    unsigned int end_seq = seq + len;  /* Can overflow */

    if (end_seq < seq) {  /* This check comes too late */
        return -1;
    }

    /* VULNERABILITY: Null pointer dereference */
    struct tcp_sock *sk = NULL;
    sk->rcv_nxt = end_seq;  /* Null pointer deref */

    /* VULNERABILITY: Division by zero */
    int mss = 0;
    int segments = len / mss;  /* Division by zero */

    return 0;
}

/* CVE-like: Memory leak in TCP */
void *tcp_alloc_skb(int size)
{
    void *skb = malloc(size);

    if (!skb)
        return NULL;

    /* VULNERABILITY: Memory leak - no corresponding free */
    void *data = malloc(size * 2);

    /* Missing: free(data) on error paths */

    return skb;
}
