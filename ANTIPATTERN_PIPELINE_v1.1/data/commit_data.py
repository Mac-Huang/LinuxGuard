#!/usr/bin/env python3
"""
Commit data for use-after-free vulnerability fix analysis
"""

COMMIT_HASH = "80af3745ca465c6c47e833c1902004a7fa944f37"
COMMIT_AUTHOR = "Dan Carpenter <dan.carpenter@linaro.org>"
COMMIT_DATE = "Fri Aug 22 11:08:46 2025 +0300"
COMMIT_MESSAGE = """of: dynamic: Fix use after free in of_changeset_add_prop_helper()

If the of_changeset_add_property() function call fails, then this code
frees "new_pp" and then dereference it on the next line.  Return the
error code directly instead.

Fixes: c81f6ce16785 ("of: dynamic: Fix memleak when of_pci_add_properties() failed")
Signed-off-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://lore.kernel.org/r/aKgljjhnpa4lVpdx@stanley.mountain
Signed-off-by: Rob Herring (Arm) <robh@kernel.org>"""

COMMIT_DIFF = """diff --git a/drivers/of/dynamic.c b/drivers/of/dynamic.c
index dd30b7d8b5e4..2eaaddcb0ec4 100644
--- a/drivers/of/dynamic.c
+++ b/drivers/of/dynamic.c
@@ -935,13 +935,15 @@ static int of_changeset_add_prop_helper(struct of_changeset *ocs,
 		return -ENOMEM;
 
 	ret = of_changeset_add_property(ocs, np, new_pp);
-	if (ret)
+	if (ret) {
 		__of_prop_free(new_pp);
+		return ret;
+	}
 
 	new_pp->next = np->deadprops;
 	np->deadprops = new_pp;
 
-	return ret;
+	return 0;
 }"""

FILE_PATH = "drivers/of/dynamic.c"
FUNCTION_NAME = "of_changeset_add_prop_helper"
VULNERABILITY_TYPE = "use-after-free"