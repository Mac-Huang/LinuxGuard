
// Detect use after kfree
@@
expression E;
@@

kfree(E);
<...
* E->...
...>

// Detect use after free
@@
expression E;
@@

free(E);
<...
* E->...
...>

// Detect double free
@@
expression E;
@@

kfree(E);
...
* kfree(E);
