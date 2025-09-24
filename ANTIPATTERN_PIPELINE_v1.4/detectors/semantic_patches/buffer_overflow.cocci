
// Detect unsafe string functions
@@
expression dst, src;
@@

* strcpy(dst, src)

@@
expression dst, src;
@@

* strcat(dst, src)

@@
expression dst, src;
@@

* sprintf(dst, src, ...)

// Detect unchecked array access
@@
expression E1, E2;
identifier arr;
@@

* arr[E1] = E2;
... when != if (E1 < ...)
    when != if (E1 >= ...)

// Detect potentially unsafe memcpy
@@
expression dst, src, size;
@@

* memcpy(dst, src, size)
... when != if (size <= ...)
    when != if (size < ...)
