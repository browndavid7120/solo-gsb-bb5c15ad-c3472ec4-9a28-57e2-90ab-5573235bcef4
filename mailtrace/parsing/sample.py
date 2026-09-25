"""页面“填入示例”按钮使用的示例邮件头。"""

SAMPLE_HEADERS = """\
Return-Path: <sender@example.com>
Received: from mailbox.final.example (127.0.0.1)
	by mailbox.final.example (Dovecot) with LMTP id zX92kQ
	for <user@final.example>; Tue, 23 Sep 2026 10:02:10 +0800 (CST)
Received: from mx1.final.example (mx1.final.example [198.51.100.10])
	by mailbox.final.example (Postfix) with ESMTPS id 7F3A2C9
	for <user@final.example>; Tue, 23 Sep 2026 10:02:10 +0800
Received: from relay2.provider.example (relay2.provider.example [203.0.113.22])
	by mx1.final.example (Postfix) with ESMTP id B4D91
	for <user@final.example>; Tue, 23 Sep 2026 10:02:05 +0800
Received: from relay1.provider.example (relay1.provider.example
	[203.0.113.11])
	by relay2.provider.example (Postfix) with ESMTP id 99C10
	for <user@final.example>; Tue, 23 Sep 2026 02:01:55 +0000 (UTC)
Received: from outgoing.example.org (outgoing.example.org [192.0.2.50])
	by relay1.provider.example (Postfix) with ESMTP id 41AB8
	for <user@final.example>; Tue, 23 Sep 2026 02:01:30 +0000
Received: from smtp01.corp.example.net (smtp01.corp.example.net [10.10.0.5])
	by outgoing.example.org with ESMTP
	for user@final.example
Received: from [10.10.0.5] (helo=smtp01.corp.example.net)
	by smtp01.corp.example.net with ESMTP id 88FF21
	for user@final.example; not-a-valid-date (server clock lost)
Date: Tue, 23 Sep 2026 02:00:00 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: Delivery path demo
	with folding
Message-ID: <demo@example.com>
"""

# 对照示例（B 侧）：与 SAMPLE_HEADERS 同一条投递链路，但
# - 开头多一跳 smtp00 -> smtp01（新增节点，且与既有 smtp01 同名，演示保序对齐）；
# - 末尾少了 Dovecot LMTP 一跳（缺失节点）；
# - 各跳时间不同（演示相邻耗时差值），smtp01 一跳时间有效而 A 侧无效（不可比较）。
SAMPLE_HEADERS_B = """\
Return-Path: <sender@example.com>
Received: from mx1.final.example (mx1.final.example [198.51.100.10])
	by mailbox.final.example (Postfix) with ESMTPS id 8C11D2
	for <user@final.example>; Tue, 23 Sep 2026 10:02:12 +0800
Received: from relay2.provider.example (relay2.provider.example [203.0.113.22])
	by mx1.final.example (Postfix) with ESMTP id C5E20
	for <user@final.example>; Tue, 23 Sep 2026 10:02:06 +0800
Received: from relay1.provider.example (relay1.provider.example [203.0.113.11])
	by relay2.provider.example (Postfix) with ESMTP id A1B33
	for <user@final.example>; Tue, 23 Sep 2026 02:01:58 +0000 (UTC)
Received: from outgoing.example.org (outgoing.example.org [192.0.2.50])
	by relay1.provider.example (Postfix) with ESMTP id 55BC9
	for <user@final.example>; Tue, 23 Sep 2026 02:01:33 +0000
Received: from smtp01.corp.example.net (smtp01.corp.example.net [10.10.0.5])
	by outgoing.example.org with ESMTP id 77D21
	for user@final.example; Tue, 23 Sep 2026 02:00:40 +0000
Received: from [10.10.0.5] (helo=smtp01.corp.example.net)
	by smtp01.corp.example.net with ESMTP id 91AA02
	for user@final.example; Tue, 23 Sep 2026 02:00:12 +0000
Received: from smtp00.corp.example.net (smtp00.corp.example.net [10.10.0.9])
	by smtp01.corp.example.net with ESMTP id 02BB77
	for user@final.example; Tue, 23 Sep 2026 02:00:05 +0000
Date: Tue, 23 Sep 2026 02:00:00 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: Delivery path demo
"""


# 多封慢段归因示例：三封走同一条 edge -> mid -> final 链路的邮件，
# 用页面规范分隔符 BATCH_DELIMITER（===== 下一封邮件 =====）分开。
# - 邮件 1：正常投递，mid->final 段耗时 150 秒；
# - 邮件 2：edge->mid 耗时 600 秒（最慢段），mid->final 时间倒灌 -20 秒（排除）；
# - 邮件 3：mid->final 段时间无效（排除）；退信后发件方从同一 IP 重新注入，
#   edge->mid 同键区段在本封内出现两次（60 秒、150 秒），仅取最大有效
#   非负耗时 150 秒作为该邮件样本；退信/重注入路径另有仅本封出现的
#   mid->edge 回流段（60 秒）。
SAMPLE_HEADERS_BATCH = """\
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M1C
\t; Tue, 23 Sep 2026 02:06:30 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M1B
\t; Tue, 23 Sep 2026 02:04:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M1A
\t; Tue, 23 Sep 2026 02:03:00 +0000
Date: Tue, 23 Sep 2026 02:03:00 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 1
===== 下一封邮件 =====
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M2C
\t; Tue, 23 Sep 2026 02:13:40 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M2B
\t; Tue, 23 Sep 2026 02:14:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M2A
\t; Tue, 23 Sep 2026 02:04:00 +0000
Date: Tue, 23 Sep 2026 02:04:00 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 2
===== 下一封邮件 =====
Received: from mid.example (mid.example [198.51.100.20])
\tby final.example with ESMTP id M3D
\t; not-a-valid-date (clock lost on final)
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M3C
\t; Tue, 23 Sep 2026 02:21:00 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M3B
\t; Tue, 23 Sep 2026 02:18:30 +0000
Received: from edge.example (edge.example [198.51.100.10])
\tby mid.example with ESMTP id M3A2
\t; Tue, 23 Sep 2026 02:17:30 +0000
Received: from sender.example (sender.example [203.0.113.50])
\tby edge.example with ESMTP id M3A
\t; Tue, 23 Sep 2026 02:16:30 +0000
Date: Tue, 23 Sep 2026 02:16:30 +0000
From: sender@example.com
To: user@final.example
Subject: batch message 3
"""

# ARC 链结构检查示例：完整的两实例 ARC 链（i=1 为首个实例，cv=none；
# i=2 为后续实例，cv=pass）。ARC 字段由接收方在顶部追加，因此原文中
# i=2 的字段组写在 i=1 之前；字段含折行，且 i=1 的 ARC-Seal 故意把
# cv 写在 i 前面（解析与标签书写顺序无关）。
SAMPLE_HEADERS_ARC = """\
ARC-Seal: i=2; a=rsa-sha256; t=1790216000; cv=pass;
\td=relay.provider.example; s=arc2026;
\tb=Pm9fKq2wRelaySealSignature==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed;
\td=relay.provider.example; s=arc2026; t=1790216000;
\tbh=3vBsRelayBodyHash==; h=From:To:Subject:Date;
\tb=Zq8wRelayMessageSignature==
ARC-Authentication-Results: i=2; relay.provider.example;
\tspf=pass smtp.mailfrom=example.com;
\tdkim=pass header.d=example.com; dmarc=pass header.from=example.com
ARC-Seal: cv=none; i=1; a=rsa-sha256; t=1790215940;
\td=mx.final.example; s=arc2026; b=Xy7zEdgeSealSignature==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
\td=mx.final.example; s=arc2026; t=1790215940;
\tbh=9wQzEdgeBodyHash==; h=From:To:Subject:Date;
\tb=Mn4vEdgeMessageSignature==
ARC-Authentication-Results: i=1; mx.final.example;
\tspf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com
Received: from relay.provider.example (relay.provider.example [203.0.113.22])
\tby mx.final.example with ESMTPS id A1B2C3
\tfor <user@final.example>; Thu, 24 Sep 2026 02:13:20 +0000
Date: Thu, 24 Sep 2026 02:12:40 +0000
From: Sender <sender@example.com>
To: User <user@final.example>
Subject: ARC chain demo
Message-ID: <arc-demo@example.com>
"""

# DKIM 头字段覆盖审计示例：两条 DKIM-Signature（由后到先的中继依次在顶部
# 追加，因此原文中转发方签名写在原始签名之前），字段名大小写与折行不影响解析。
# - 签名 2（example.com，第 2 个字段）h= 里 Received 出现两次：按 RFC 6376
#   自底部向上匹配，分别命中第 4、第 3 个字段（两个 Received 副本），
#   重复字段名不按集合合并；From/To/Subject/Date 各匹配一次。
# - 签名 1（forwarder.example，顶部字段）对第 2 条签名做了 countersignature
#   （h= 中含 dkim-signature，自底部向上命中第 2 条签名而不会匹配自身），
#   但未覆盖 To 与 Date，且多写了一个不存在的 X-Missing 字段。
# - To 有两个实际副本：转发时被注入到顶部的 extra-injected（第 7 个字段）
#   与原始的 User（第 8 个字段）；两条签名的 h= 都只有一个 To，自底部向上
#   命中原始副本后，被注入的第 7 个副本对每条签名都显示为“未覆盖”。
SAMPLE_HEADERS_DKIM = """\
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
\td=forwarder.example; s=sel2; t=1790216000;
\tbh=Rm9yd2FyZGVyQm9keUhhc2g=;
\th=Received:Received:DKIM-Signature:From:Subject:X-Missing;
\tb=Rm9yd2FyZGVyU2lnbmF0dXJl
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
\td=example.com; s=sel1; t=1790215940;
\tbh=T3JpZ2luYWxCb2R5SGFzaA==;
\th=Received:Received:From:To:Subject:Date:Message-ID;
\tb=T3JpZ2luYWxTaWduYXR1cmU=
Received: from mx.forwarder.example (mx.forwarder.example [198.51.100.8])
\tby gateway.final.example with ESMTPS id F9E8D7
\tfor <user@final.example>; Thu, 24 Sep 2026 02:13:30 +0000
Received: from relay.provider.example (relay.provider.example [203.0.113.22])
\tby mx.forwarder.example with ESMTPS id C6B5A4
\tfor <user@final.example>; Thu, 24 Sep 2026 02:13:00 +0000
Date: Thu, 24 Sep 2026 02:12:40 +0000
From: Sender <sender@example.com>
To: extra-injected@evil.example
To: User <user@final.example>
Subject: DKIM coverage demo
Message-ID: <dkim-demo@example.com>
"""

# 接收链可信边界示例：
# 头部自上而下的 by 主机为
#   edge.internal.corp -> gw2.internal.corp -> relay2.partner.example
#   -> gw2.internal.corp（边界之外再次出现本组织主机名：外部主机冒用 /
#      伪造的 Received，不得重新接入可信链）-> edge.external.example
# 本组织名单 edge.internal.corp / gw2.internal.corp 命中前两跳，
# 边界在第 3 跳（relay2.partner.example），最后可信跳（第 2 跳）记录的
# from 主机 gateway.partner.example 与对端 IP 203.0.113.55 即外部交接点；
# 第 4 跳 by 虽再次命中名单，也明确标记为“边界之后，不重新接入”。
SAMPLE_HEADERS_TRUST = """\
Received: from gw2.internal.corp (gw2.internal.corp [10.20.0.2])
\tby edge.internal.corp (Postfix) with ESMTPS id A101
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:05:10 +0000
Received: from gateway.partner.example (gateway.partner.example [203.0.113.55])
\tby gw2.internal.corp (Postfix) with ESMTP id B202
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:04:30 +0000
Received: from relay1.external.example (relay1.external.example [198.51.100.20])
\tby relay2.partner.example (Postfix) with ESMTP id C303
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:03:50 +0000
Received: from edge.external.example (edge.external.example [192.0.2.77])
\tby gw2.internal.corp (Postfix) with ESMTP id D404
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:03:00 +0000
Received: from sender.external.example (sender.external.example [192.0.2.90])
\tby edge.external.example (Postfix) with ESMTP id E505
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:02:10 +0000
Date: Thu, 24 Sep 2026 03:02:00 +0000
From: Sender <sender@external.example>
To: User <user@corp.example>
Subject: Trust boundary demo
Message-ID: <trust-demo@external.example>
"""

# 本组织接收服务器主机名示例名单（每行一个；末尾点演示规范化去重）
SAMPLE_TRUSTED_HOSTS = """\
edge.internal.corp
GW2.Internal.Corp.
"""

# 认证结果来源示例（与可信边界示例同一条链路，可信前缀为
# edge.internal.corp / gw2.internal.corp 两跳）：
# - 第 1 条 AR（mx.forged.example）：其后紧邻的 Received 是第 1 跳
#   （可信），但 authserv-id 与该跳 by 主机不一致 → 身份不符；
# - 第 2 条 AR（edge.internal.corp）：归属第 1 跳 → 本组织声明，
#   含两条 dkim 声明（pass / fail 各一，按原文顺序保留重复）；
# - 第 3 条 AR（gw2.internal.corp）：归属第 2 跳 → 本组织声明；
# - 第 4 条 AR（relay2.partner.example）：对应第 3 跳（即可信边界）
#   → 越过边界；
# - 第 5 条 AR（gw2.internal.corp）：对应第 4 跳（边界之后再次冒用
#   本组织主机名的伪造 Received）→ 越过边界（authserv-id 与 by
#   一致也不接入）；
# - 第 6 条 AR（archive.external.example）：写在最后一条 Received
#   之下 → 无对应跳。
SAMPLE_HEADERS_AUTHRES = """\
Authentication-Results: mx.forged.example;
\tspf=pass smtp.mailfrom=spoof.example; dmarc=pass header.from=spoof.example
Authentication-Results: edge.internal.corp;
\tspf=pass smtp.mailfrom=partner.example;
\tdkim=pass header.d=partner.example; dkim=fail header.d=attacker.example;
\tdmarc=pass header.from=partner.example
Received: from gw2.internal.corp (gw2.internal.corp [10.20.0.2])
\tby edge.internal.corp (Postfix) with ESMTPS id A101
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:05:10 +0000
Authentication-Results: gw2.internal.corp;
\tspf=softfail smtp.mailfrom=partner.example;
\tdkim=pass header.d=partner.example; dmarc=fail header.from=partner.example
Received: from gateway.partner.example (gateway.partner.example [203.0.113.55])
\tby gw2.internal.corp (Postfix) with ESMTP id B202
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:04:30 +0000
Authentication-Results: relay2.partner.example;
\tspf=pass smtp.mailfrom=external.example;
\tdkim=pass header.d=external.example; dmarc=pass header.from=external.example
Received: from relay1.external.example (relay1.external.example [198.51.100.20])
\tby relay2.partner.example (Postfix) with ESMTP id C303
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:03:50 +0000
Authentication-Results: gw2.internal.corp; spf=pass smtp.mailfrom=spoof.example
Received: from edge.external.example (edge.external.example [192.0.2.77])
\tby gw2.internal.corp (Postfix) with ESMTP id D404
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:03:00 +0000
Received: from sender.external.example (sender.external.example [192.0.2.90])
\tby edge.external.example (Postfix) with ESMTP id E505
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:02:10 +0000
Authentication-Results: archive.external.example; spf=none
Date: Thu, 24 Sep 2026 03:02:00 +0000
From: Sender <sender@external.example>
To: User <user@corp.example>
Subject: Authentication-Results source demo
Message-ID: <authres-demo@external.example>
"""

# 发件域对齐审计示例（与认证结果来源示例同一条链路，可信前缀为
# edge.internal.corp / gw2.internal.corp 两跳；From 域为
# mail.partner.example，发件组织域填 partner.example）：
# - 第 1 条 AR（edge.internal.corp，本组织声明，归属第 1 跳）：
#   spf=pass smtp.mailfrom=partner.example、dkim=pass
#   header.d=partner.example（严格模式下与 From 域 mail.partner.example
#   不完全相同 → 不对齐；宽松模式下均为组织域 partner.example 或其子域
#   → 对齐）；dkim=fail 不是通过声明，不参与对齐；
# - 第 2 条 AR（gw2.internal.corp，本组织声明，归属第 2 跳）：
#   spf=pass smtp.mailfrom=bounce.partner.example（同样仅宽松模式对齐）；
# - 第 3 条 AR（relay2.partner.example）：对应第 3 跳（可信边界之外），
#   虽然 dkim=pass header.d=mail.partner.example 与 From 域完全相同，
#   但不是本组织声明，**不采纳**；
# 因此同一份头部：严格模式结论为“未见对齐证据”，宽松模式（组织域
# partner.example）结论为“有对齐证据”。
SAMPLE_HEADERS_ALIGN = """\
Authentication-Results: edge.internal.corp;
\tspf=pass smtp.mailfrom=partner.example;
\tdkim=pass header.d=partner.example; dkim=fail header.d=attacker.example;
\tdmarc=pass header.from=mail.partner.example
Received: from gw2.internal.corp (gw2.internal.corp [10.20.0.2])
\tby edge.internal.corp (Postfix) with ESMTPS id A101
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:05:10 +0000
Authentication-Results: gw2.internal.corp;
\tspf=pass smtp.mailfrom=bounce.partner.example
Received: from gateway.partner.example (gateway.partner.example [203.0.113.55])
\tby gw2.internal.corp (Postfix) with ESMTP id B202
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:04:30 +0000
Authentication-Results: relay2.partner.example;
\tdkim=pass header.d=mail.partner.example;
\tspf=pass smtp.mailfrom=mail.partner.example
Received: from relay1.external.example (relay1.external.example [198.51.100.20])
\tby relay2.partner.example (Postfix) with ESMTP id C303
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:03:50 +0000
Received: from sender.external.example (sender.external.example [192.0.2.90])
\tby edge.external.example (Postfix) with ESMTP id E505
\tfor <user@corp.example>; Thu, 24 Sep 2026 03:02:10 +0000
Date: Thu, 24 Sep 2026 03:02:00 +0000
From: Partner News <news@mail.partner.example>
To: User <user@corp.example>
Subject: From alignment demo
Message-ID: <align-demo@mail.partner.example>
"""

# 发件组织域示例（宽松模式必填；上例 From 域 mail.partner.example 是其子域）
SAMPLE_ORG_DOMAIN = "partner.example"


