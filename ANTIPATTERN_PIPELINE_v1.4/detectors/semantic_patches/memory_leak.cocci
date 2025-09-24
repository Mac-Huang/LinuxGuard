
// Detect memory allocation without corresponding free
@@
expression E;
identifier f;
@@

E = \(kmalloc\|kzalloc\|kcalloc\|vmalloc\)(...)
... when != kfree(E)
    when != vfree(E)
    when exists
* return ...;

// Detect allocation in loop without free
@@
expression E;
@@

while (...) {
  ...
  E = \(kmalloc\|kzalloc\)(...)
  ... when != kfree(E)
}
