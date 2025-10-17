
/* Test case for use-after-free vulnerability
 * Pattern: The code frees a memory block (new_pp) and then immediately attempts to dereference it on the next line if of_changeset_add_property() fails.
 * Code context from bug: if (ret)
		__of_prop_free(new_pp);

	new_pp->next = np->deadprops;
 */

#include <stdlib.h>
#include <stdio.h>

struct property {
    char *name;
    int length;
    void *value;
    struct property *next;
};

struct device_node {
    const char *name;
    struct property *properties;
    struct property *deadprops;
};

// Mock function that sometimes fails
int of_changeset_add_property(void *changeset, struct property *prop) {
    // Simulate occasional failure
    static int call_count = 0;
    return (++call_count % 2) ? -1 : 0;  // Fails every other call
}

// Mock free function
void __of_prop_free(struct property *prop) {
    if (prop) {
        free(prop);
    }
}

// Vulnerable function matching the exact pattern
void vulnerable_pattern_test(struct device_node *np) {
    struct property *new_pp = malloc(sizeof(struct property));
    int ret;

    if (!new_pp)
        return;

    new_pp->name = "test_property";
    new_pp->length = 0;
    new_pp->value = NULL;
    new_pp->next = NULL;

    // The exact vulnerable pattern from the commit
    ret = of_changeset_add_property(NULL, new_pp);
    if (ret)
        __of_prop_free(new_pp);  // Free on error

    new_pp->next = np->deadprops;  // USE AFTER FREE - new_pp was freed above!
    np->deadprops = new_pp;
}

int main() {
    struct device_node node = {"test_node", NULL, NULL};
    vulnerable_pattern_test(&node);
    return 0;
}
