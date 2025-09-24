/* Linux kernel driver simulation */
#include <stdio.h>
#include <string.h>

/* CVE-like: Format string vulnerability */
void driver_log_message(char *user_msg)
{
    char log_buf[512];

    /* VULNERABILITY: Format string bug */
    sprintf(log_buf, user_msg);  /* User controlled format string */

    /* Should be: sprintf(log_buf, "%s", user_msg); */

    printf(log_buf);  /* Another format string vulnerability */
}

/* CVE-like: Off-by-one error */
int driver_copy_data(char *dst, char *src, int size)
{
    int i;

    /* VULNERABILITY: Off-by-one error */
    for (i = 0; i <= size; i++) {  /* Should be i < size */
        dst[i] = src[i];
    }

    return 0;
}
