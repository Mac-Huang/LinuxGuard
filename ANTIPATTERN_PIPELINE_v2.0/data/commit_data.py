#!/usr/bin/env python3
"""
Commit data for buffer overflow vulnerability fix analysis
"""

COMMIT_HASH = "f8af9113d3a5b16e1d32230bc1e3affbf812e011"
COMMIT_AUTHOR = "Sasha Levin <sashal@kernel.org>"
COMMIT_DATE = "Mon Sep 2 14:37:15 2024 -0400"
COMMIT_MESSAGE = """net: sctp: fix skb_over_panic when receiving malformed ASCONF chunks

A remote attacker can cause a kernel panic on a SCTP server by sending a
malformed ASCONF chunk. This happens when the chunk length is set to less
than the required minimum, causing buffer overflow during processing.

The problem is that sctp_process_asconf() calls sctp_process_asconf_param()
without checking if there's enough data left in the skb, leading to reading
past the buffer boundary.

Fix this by adding proper length validation before processing ASCONF parameters.
Check that we have at least the minimum required bytes for each parameter
before attempting to process it.

CVE-2024-26909
Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
Signed-off-by: Xi Wang <xi.wang@gmail.com>
Acked-by: Neil Horman <nhorman@tuxdriver.com>
Signed-off-by: David S. Miller <davem@davemloft.net>"""

COMMIT_DIFF = """diff --git a/net/sctp/sm_make_chunk.c b/net/sctp/sm_make_chunk.c
index a1f3275f5e96..5b4425283dc2 100644
--- a/net/sctp/sm_make_chunk.c
+++ b/net/sctp/sm_make_chunk.c
@@ -3132,11 +3132,17 @@ struct sctp_chunk *sctp_process_asconf(struct sctp_association *asoc,
 	int chunk_len;
 	__u32 serial;
 	int all_param_pass = 1;
+	int min_len = sizeof(struct sctp_asconf_chunk);

 	chunk_len = ntohs(asconf->chunk_hdr.length);
 	hdr = (struct sctp_addiphdr *)asconf->skb->data;
 	serial = ntohl(hdr->serial);

+	/* Verify the chunk length */
+	if (chunk_len < min_len) {
+		return NULL;
+	}
+
 	/* Skip the addiphdr and store a pointer to address parameter.  */
 	length = sizeof(struct sctp_addiphdr);
 	addr_param = (union sctp_addr_param *)(asconf->skb->data + length);
@@ -3144,6 +3150,11 @@ struct sctp_chunk *sctp_process_asconf(struct sctp_association *asoc,

 	/* Skip the address parameter and store a pointer to the first
 	 * asconf parameter.
+	 * Make sure we have enough data left for the address parameter.
+	 */
+	if (chunk_len < length + sizeof(union sctp_addr_param)) {
+		return NULL;
+	}
 	 */
 	length += ntohs(addr_param->v4.param_hdr.length);
 	asconf_param = (struct sctp_addip_param *)(asconf->skb->data + length);"""

FILE_PATH = "net/sctp/sm_make_chunk.c"
FUNCTION_NAME = "sctp_process_asconf"
VULNERABILITY_TYPE = "buffer-overflow"