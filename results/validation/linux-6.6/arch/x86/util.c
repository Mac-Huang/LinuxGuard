// Mock Linux kernel file for version 6.6
// Directory: arch/x86
// File: util.c

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

// Sample function that might contain anti-patterns
void *sample_alloc_function(size_t size) {
    void *ptr = kmalloc(size, GFP_KERNEL);
    // Potential issue: missing null check
    return ptr;
}

void sample_free_function(void *ptr) {
    // Potential issue: missing null check before free
    kfree(ptr);
}

// Sample function with locking
void sample_lock_function(struct mutex *lock) {
    mutex_lock(lock);
    // Critical section
    // Potential issue: missing unlock in error path
    if (some_condition()) {
        return; // Missing mutex_unlock!
    }
    mutex_unlock(lock);
}

static int __init sample_init(void) {
    printk(KERN_INFO "Sample module loaded for kernel 6.6\n");
    return 0;
}

static void __exit sample_exit(void) {
    printk(KERN_INFO "Sample module unloaded for kernel 6.6\n");
}

module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sample module for validation");
