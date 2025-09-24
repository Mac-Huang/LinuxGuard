
// Detect potential race conditions with locks
@@
expression lock;
@@

\(mutex_unlock\|spin_unlock\)(lock);
...
\(mutex_lock\|spin_lock\)(lock);

// Detect TOCTOU pattern
@@
expression E;
statement S;
@@

if (E) S
...
* E = ...
