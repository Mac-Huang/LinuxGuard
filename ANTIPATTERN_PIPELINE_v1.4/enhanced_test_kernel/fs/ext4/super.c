/* Linux kernel fs/ext4/super.c simulation */
#include <pthread.h>
#include <stdlib.h>

struct super_block {
    int s_flags;
    void *s_fs_info;
    pthread_mutex_t s_lock;
};

static struct super_block *global_sb = NULL;

/* CVE-like: Race condition in filesystem operations */
int ext4_mount(struct super_block *sb)
{
    /* VULNERABILITY: Race condition - check without lock */
    if (global_sb != NULL) {  /* Check */
        return -1;
    }

    /* Time window for race condition */

    pthread_mutex_lock(&sb->s_lock);
    global_sb = sb;  /* Set - TOCTOU vulnerability */
    pthread_mutex_unlock(&sb->s_lock);

    return 0;
}

/* CVE-like: Uninitialized variable use */
int ext4_read_inode(int ino)
{
    int ret;  /* VULNERABILITY: Uninitialized */
    void *data;

    if (ino < 0)
        return ret;  /* Using uninitialized variable */

    data = malloc(4096);
    /* VULNERABILITY: Missing null check */
    memset(data, 0, 4096);  /* Potential null deref if malloc fails */

    return 0;
}
