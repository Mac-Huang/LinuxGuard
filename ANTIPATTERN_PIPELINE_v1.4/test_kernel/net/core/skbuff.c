/* Test kernel file - net/core/skbuff.c */
#include <linux/skbuff.h>
#include <linux/string.h>

void skb_copy_bits(struct sk_buff *skb, int offset, void *to, int len)
{
    char buffer[256];
    strcpy(buffer, to);  // Buffer overflow vulnerability

    if (!skb)
        return;

    memcpy(to, skb->data + offset, len);  // Potential overflow
}

void skb_free(struct sk_buff *skb)
{
    kfree(skb);
    skb->next = NULL;  // Use after free
}
