
// Detect null pointer dereference
@@
expression E;
@@

E = NULL;
<...
* E->...
...>

// Detect missing null check
@@
expression E;
identifier f;
@@

E = f(...);
... when != if (E == NULL) ...
    when != if (!E) ...
* E->...

// Detect inconsistent null checking
@@
expression E;
@@

if (E == NULL) { ... }
<...
* E->...
...>
