/* Linux kernel net/core/skbuff.c simulation */
#include <string.h>
#include <stdlib.h>

struct sk_buff {
    unsigned char *data;
    unsigned int len;
    struct sk_buff *next;
};

/* CVE-like: Buffer overflow in skb_copy */
int skb_copy_bits(struct sk_buff *skb, int offset, void *to, int len)
{
    char temp[256];  /* Fixed size buffer */

    if (!skb || !to)
        return -1;

    /* VULNERABILITY: No bounds checking */
    memcpy(temp, skb->data + offset, len);  /* Buffer overflow if len > 256 */

    /* VULNERABILITY: strcpy without bounds */
    char dest[100];
    strcpy(dest, (char*)to);  /* Buffer overflow */

    return 0;
}

/* CVE-like: Use-after-free in skb handling */
void skb_release(struct sk_buff *skb)
{
    if (skb) {
        free(skb->data);
        skb->data = NULL;
    }

    free(skb);
    /* VULNERABILITY: Use after free */
    skb->next = NULL;  /* Writing to freed memory */
}
