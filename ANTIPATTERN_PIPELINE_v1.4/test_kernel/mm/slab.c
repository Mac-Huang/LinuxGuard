/* Test kernel file - mm/slab.c */
void *kmem_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
    void *ptr = malloc(cache->size);

    if (!ptr)
        return NULL;

    // Simulate use after free
    free(ptr);
    memset(ptr, 0, cache->size);  // Use after free

    return ptr;
}
