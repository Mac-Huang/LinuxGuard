/* Linux kernel mm/slab.c simulation */
#include <stdlib.h>
#include <string.h>

struct kmem_cache {
    size_t size;
    void *freelist;
};

/* CVE-like: Use-after-free in slab allocator */
void *kmem_cache_alloc(struct kmem_cache *cachep, unsigned int flags)
{
    void *objp = malloc(cachep->size);

    if (!objp)
        return NULL;

    /* Simulate complex allocation logic */
    void *temp = objp;
    free(temp);

    /* VULNERABILITY: Use after free */
    memset(objp, 0, cachep->size);  /* Writing to freed memory */

    return objp;
}

/* CVE-like: Double free vulnerability */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
    if (!objp)
        return;

    free(objp);

    /* VULNERABILITY: Potential double free */
    if (cachep->freelist == objp) {
        free(objp);  /* Double free */
    }
}
