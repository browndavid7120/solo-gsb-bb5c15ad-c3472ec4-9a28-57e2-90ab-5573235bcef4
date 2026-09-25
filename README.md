# 📮 MailTrace — 邮件投递路径检查器

一个轻量的 Python Flask 网页应用，帮助开发者检查邮件**原始头部**（raw headers）的投递路径：

- 自动处理 **折行（folding）字段**，按 RFC 5322 展开续行；
- 提取每一个 `Received` 字段中的时间戳，统一换算为 **UTC**；
- 按邮件**实际投递先后**排列中继节点（发件方 → 收件方），而不是按头部里的书写顺序；
- 计算并展示**相邻节点耗时**（含端到端总耗时）；
- **无法解析的时间标记为异常，但保留原始字段**（可展开查看）；
- **缺少时间的节点仍然列出**，不会被丢弃；
- 识别时钟偏移/时间倒灌（上一节点时间晚于本节点）并告警；
- 提取 `from` / `by` / `via` / `with` / `id` 与对端 IPv4/IPv6 地址；
- **双邮件头路径对照**：分别粘贴两份头部，复用同一套 Received 解析结果，
  按投递结构顺序对中继节点做**保序全局对齐**，并列展示**共有 / 新增（仅 B）/ 缺失（仅 A）**节点；
  共有节点展示两份各自的相邻耗时与差值（B−A），任一侧时间无效时明确显示“不可比较”。
- **多封邮件慢段归因**：页面一次粘贴**至少三份**用分隔行分开的原始头部
  （`===== 下一封邮件 =====`，也支持 `---`、`###`、`***` 等分隔行），
  或调用 `POST /api/batch-delays`（`headers` 字符串数组），复用同一套
  Received 解析，按各邮件投递顺序中**实际相邻的两个节点**聚合慢段，
  输出每段的样本数、中位耗时、最大耗时（从慢到快排序），并统计
  因时间无效 / 时间倒灌被排除的区段数。
- **单封邮件脱敏分享**：分析页点击 **“下载脱敏报告”**（或调用
  `POST /api/analyze/share`，输入 `headers` 字符串），按投递顺序为不同
  主机名、IP 分别分配**本次请求内稳定**的 `H1`、`IP1` 等别名；同一值在
  节点、来源与上一跳标签中保持一致，缺失值留空。报告**仅白名单输出**
  路径顺序、别名、UTC 时间、相邻耗时及异常级别与说明，不含原始头部、
  邮件摘要、Received ID 等可识别文本；没有 `Received` 字段时返回 400。
- **ARC 链结构检查**（RFC 8617）：复用同一套折行展开解析，按 `i` 标签把
  `ARC-Seal` / `ARC-Message-Signature` / `ARC-Authentication-Results`
  归组为 ARC 实例，校验每个实例三类字段各一条、实例号从 1 开始连续、
  首个实例（i=1）的 Seal `cv=none`（后续实例为 `pass`）；非法 `i`、
  字段重复 / 缺失、跳号、`cv` 异常逐项定位到具体实例与字段，
  折行与标签书写顺序变化不影响识别；完全没有 ARC 字段时报告
  **“无 ARC 链”**（不判定通过）。页面粘贴检查或调用
  `POST /api/arc/check`（输入 `headers` 字符串，返回同结构 JSON）。
- **DKIM 头字段覆盖审计**（RFC 6376）：复用同一套折行展开解析，逐条读取
  每一条 `DKIM-Signature` 的 `h=` 列表；**每条签名独立**按列表顺序、自
  头部**底部向上**为同名项匹配尚未被本签名使用的实际字段，并记录字段位置
  （重复字段名不按集合合并，多个同名副本从最新一条开始依次占用）。页面与
  `POST /api/dkim/coverage` 展示每条签名的逐项匹配结果、未匹配的 `h=` 项，
  以及 `From` / `Subject` / `To` / `Date` 中未被该签名覆盖的实际副本；
  完全没有签名时报告**“无 DKIM 签名”**（独立状态），缺失或空 `h=` 标为
  异常。结果**只表示字段覆盖，不宣称签名真伪**（不验证 `b=` 签名值）。
- **接收链可信边界**（单封邮件）：在页面 **“接收链可信边界”** 文本框粘贴
  一份原始头部并填写**本组织接收服务器主机名名单**（每行一个，也兼容逗号 /
  空白分隔），或调用 `POST /api/analyze/trust-boundary`
  （`headers` 字符串 + `trusted_hosts` 字符串数组）。系统复用同一套
  Received 解析，从头部**最上方**（最终接收服务器最新追加的一条）开始向下
  逐跳检查 `by` 主机名：只有**自顶端连续命中**名单的跳标记为可信，首个
  未命中或缺少 `by` 的跳即为可信**边界**；边界之后即使 `by` 再次命中名单
  也**不会重新接入**（`reentry_listed` 显式标出）。页面 / JSON 展示每跳
  可信状态、边界位置（头部自上而下第几跳），以及**最后可信跳**记录的
  `from` 主机与对端 IP——即邮件进入本组织的**外部交接点**。主机名比较
  忽略大小写与末尾点；空名单返回 400 输入错误；顶端未命中或没有
  `Received` 字段时分别以 `untrusted_top` / `no_received` 状态明确提示
  **无法建立可信链**。
- **认证结果来源（Authentication-Results 归属）**：在页面
  **“认证结果来源”** 区域粘贴原始头部并填写本组织接收服务器名单，或调用
  `POST /api/analyze/auth-results`（`headers` 字符串 + `trusted_hosts`
  字符串数组）。系统复用折行展开与可信边界分析，把每条
  `Authentication-Results` 归属到其后**紧邻的 `Received`**（两者之间不得有
  另一条 `Received`）：仅当该跳属于**自顶端连续可信前缀**、且
  `authserv-id` 与该跳 `by` 主机一致（忽略大小写与末尾点）时，才标为
  **本组织声明**；其余逐条标明**无对应跳**（其后没有任何 `Received`）、
  **越过边界**（对应跳不在连续可信前缀内）或**身份不符**（对应跳可信但
  authserv-id 与 by 主机不一致）。对本组织声明提取 `spf` / `dkim` /
  `dmarc` 的结果词，按原文顺序展示并**保留重复声明**；没有可信前缀
  （或没有任何字段归属本组织）时明确显示**无本组织声明**。
- **发件域对齐审计**（单封邮件）：在页面 **“发件域对齐审计”** 区域粘贴
  一份原始头部，填写**本组织接收服务器主机名名单**与**发件组织域**，
  或调用 `POST /api/analyze/sender-alignment`（`headers` 字符串 +
  `trusted_hosts` 字符串数组 + `mode`，宽松模式另需 `org_domain`）。
  系统复用 Authentication-Results 归属判定，**只采纳本组织声明**：取其中
  `spf=pass` 的 `smtp.mailfrom`、`dkim=pass` 的 `header.d` 身份域，
  与头部**唯一 From 地址域**比较。**严格模式**要求身份域与 From 域完全
  相同；**宽松模式**要求两域均为所填组织域或其子域（按标签边界匹配，
  `example.com` 不匹配 `notexample.com`，但匹配 `mail.example.com`）。
  任一可信通过声明对齐 → **有对齐证据**；有可用通过声明但均不对齐 →
  **未见对齐证据**；其余（无本组织声明、无 pass、pass 缺身份域、From
  重复 / 缺域等）→ **证据不足**。逐条展示方法、声明字段位置、接收跳、
  身份域及比较结果；**重复 From、缺失域绝不静默择一**。

解析核心（`mailtrace/`）仅依赖 Python 标准库，可脱离 Flask 单独使用或被其他程序导入。

---

## 一条命令启动

### 方式一：Docker Compose（推荐）

```bash
docker compose up -d --build
```

然后浏览器访问：

```
http://localhost:8000
```

### 方式二：仅用 Docker

```bash
docker build -t mailtrace . && docker run --rm -p 8000:8000 mailtrace
```

访问 `http://localhost:8000`。

> 容器在**启动时**会执行一次 `pip install -r requirements.txt`（见 `entrypoint.sh`），
> 因此即使基础镜像内没有预装依赖，依赖也会随容器启动自动安装；
> Dockerfile 在构建阶段也会预装一次以加速常规启动。
> 离线或希望跳过启动安装时，设置环境变量 `SKIP_STARTUP_INSTALL=1`。

停止服务：`docker compose down`。

启动后默认端口为 **8000**（宿主机端口可用 `HOST_PORT` 修改，见下文“访问端口”），
页面与 JSON API 地址如下：

| 用途 | 地址（默认 `http://localhost:8000`） |
| --- | --- |
| 页面（投递路径 / 对照 / 慢段归因 / ARC / DKIM 覆盖 / 可信边界 / 认证结果来源 / 发件域对齐） | `http://localhost:8000/` |
| 单份头部分析 | `POST http://localhost:8000/api/analyze` |
| 脱敏分享报告 | `POST http://localhost:8000/api/analyze/share` |
| **接收链可信边界** | `POST http://localhost:8000/api/analyze/trust-boundary` |
| **认证结果来源** | `POST http://localhost:8000/api/analyze/auth-results` |
| **发件域对齐审计** | `POST http://localhost:8000/api/analyze/sender-alignment` |
| 双邮件头路径对照 | `POST http://localhost:8000/api/compare` |
| 多封慢段归因 | `POST http://localhost:8000/api/batch-delays` |
| ARC 链结构检查 | `POST http://localhost:8000/api/arc/check` |
| **DKIM 头字段覆盖审计** | `POST http://localhost:8000/api/dkim/coverage` |
| 健康检查 | `GET http://localhost:8000/healthz` |

---

## 使用方法

1. 打开 `http://localhost:8000`；
2. 把邮件的**原始头部**（Gmail 的“显示原始邮件”、Outlook 的“查看邮件来源”等）完整粘贴到
   **头部 A** 文本框（也可以点“填入示例”，会同时填入 A、B 两份示例）；
3. 点击 **分析投递路径（A）** 查看单份头部的投递时间线；
   需要把路径**脱敏后分享**（如发给同事排查、贴到工单）时，直接点
   **“下载脱敏报告”**，浏览器会保存 `mailtrace-share-report.json`
   （基于当前“头部 A”，无需先分析；原始主机名 / IP 不会出现在报告里）；
4. 或在 **头部 B** 中粘贴另一份头部，点击 **对照 A / B 路径** 查看双邮件头对照结果；
5. 需要在**多封邮件之间定位慢段**时，把至少三份原始头部粘贴到
   **“多封邮件慢段归因”** 文本框，邮件之间单独一行写分隔符
   `===== 下一封邮件 =====`（可点“填入 3 封示例”参考格式），
   点击 **慢段归因（多封）**。
6. 需要检查 **ARC 链结构**时，把含 ARC 字段的原始头部粘贴到
   **“ARC 链结构检查”** 文本框（可点“填入示例”查看一条完整的两实例
   ARC 链），点击 **检查 ARC 链**：页面展示总状态、每个实例的三类字段
   齐全性与 Seal `cv` 校验结果，并对非法 `i`、字段重复 / 缺失、跳号、
   `cv` 异常逐项定位。
7. 需要审计 **DKIM 头字段覆盖**时，把含 `DKIM-Signature` 的原始头部粘贴到
   **“DKIM 头字段覆盖审计”** 文本框（可点“填入示例”，其中含两条签名、
   `h=` 重复字段、countersignature 与被注入的重复 `To` 副本），点击
   **审计 DKIM 覆盖**：页面逐条展示每个 `h=` 项匹配到的字段位置、未匹配
   项，以及 `From` / `Subject` / `To` / `Date` 未被该签名覆盖的实际副本。
8. 需要定位**外部交接点 / 接收链可信边界**时，在
   **“🔗 接收链可信边界（单封邮件）”** 区域把单封邮件的原始头部粘贴到
   头部文本框，并在下方**每行填写一个本组织接收服务器主机名**
   （如 `edge.internal.corp`、`gw2.internal.corp`；忽略大小写与末尾点，
   可点“填入示例”查看一条含“边界后再次命中名单”的链路），点击
   **分析可信边界**：页面按头部自上而下的顺序逐跳展示 ✓ 可信 /
   ⛔ 边界 / ✗ 边界之外状态，顶部统计连续可信跳数与边界位置，
   并以单独卡片展示**外部交接点**（最后可信跳的 `from` 主机与对端 IP）。
   顶端第一跳就未命中或缺少 `by`、以及头部完全没有 `Received` 时，
   页面会明确提示**无法建立可信链**（而不是误判为全部可信）。
9. 需要确认 **Authentication-Results 是否来自本组织**时，在
   **“🛡️ 认证结果来源”** 区域粘贴单封邮件原始头部并填写本组织接收服务器
   名单（可点“填入示例”，含身份不符、越过边界、无对应跳等各类样例），
   点击 **分析认证结果来源**：页面逐条展示每条 `Authentication-Results`
   归属的接收跳与判定（✓ 本组织声明 / ⛔ 越过边界 / ⚠ 身份不符 /
   ✗ 无对应跳），并以结果词卡片汇总本组织声明的 `spf` / `dkim` /
   `dmarc`（按原文顺序、保留重复声明）；无法建立可信前缀时明确显示
   **无本组织声明**。
10. 需要审计**发件域对齐**时，在 **“🧭 发件域对齐审计”** 区域粘贴单封
    邮件原始头部、填写本组织接收服务器名单与**发件组织域**（如
    `partner.example`），选择**严格模式**（身份域与 From 域完全相同）或
    **宽松模式**（两域均为组织域或其子域，按标签边界匹配），点击
    **审计发件域对齐**（可点“填入示例”查看两种模式下结论不同的样例）：
    页面顶部给出三选一结论（**有对齐证据 / 未见对齐证据 / 证据不足**），
    其下展示 From 域解析卡片与每条本组织 `spf` / `dkim` 声明的
    方法、声明字段位置、接收跳、身份域与比较结果；重复 From 字段、
    单字段多地址、缺地址 / 缺域时明确提示并判定证据不足，绝不静默择一。

慢段归因的聚合口径：

- 聚合单位是每封邮件投递顺序中**实际相邻的两个节点**组成的有向区段（上游 → 下游），
  不会跳过中间节点拼接耗时；
- 节点身份是**规范化 `by` 主机名与对端 IP 的完整已知字段组合**：
  主机名忽略大小写与末尾点，缺失字段保留为“未知”——因此 `(mx, 1.2.3.4)` 与
  `(mx, 未知 IP)` 属于不同节点；区段任一端完全没有身份（by 与 IP 都缺失）时，
  该区段会被计数但**不与其他邮件合并**；
- 同一封邮件里同一区段重复出现（退信、重试、绕环）时，只把其中**最大的有效非负耗时**
  作为该邮件在这一区段上的唯一样本（界面会显示归并掉的重复区段数）；
- 相邻两跳任一时间缺失 / 无法解析 → 计入“时间无效”；
  下游时间早于上游（负耗时，时间倒灌 / 时钟偏移）→ 计入“时间倒灌”，两者均不进入统计；
- 每个区段输出 **样本数、中位耗时、最大耗时**，整体按中位耗时**从慢到快**排序。

单份分析页面以时间线形式展示每个中继节点：节点名称、UTC 时间、from/by/协议、对端 IP、
距上一节点耗时、异常/告警，以及可展开的**原始 `Received` 文本（保留折行）**。

对照结果以表格并列展示（行顺序为投递顺序：发件方 → 收件方）：

- **共有**：两侧身份一致的节点（匹配依据为 `by` 主机与对端 IP，任一冲突即视为不同节点；
  同名节点重复出现时按结构顺序保序全局对齐，而非首次命中；
  `by` 与对端 IP 都缺失的节点没有身份，不会仅凭时间相近配对）；
- **新增**：仅出现在 B 侧的节点；**缺失**：仅出现在 A 侧的节点；
- 共有节点展示 A、B 各自到上一相邻节点的耗时及差值（B−A）；
  任一侧时间无效时显示“不可比较”，不会跳过中间无效节点拼接耗时。

也提供 JSON 接口，便于脚本调用：

```bash
# 单份头部分析
curl -s -X POST http://localhost:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"headers": "Received: by mx.example; Tue, 23 Sep 2026 10:00:00 +0800"}'

# 单份头部脱敏分享报告（别名化，可安全外发）
curl -s -X POST http://localhost:8000/api/analyze/share \
  -H 'Content-Type: application/json' \
  -d '{"headers": "Received: by mx.example; Tue, 23 Sep 2026 10:00:00 +0800"}'

# 双邮件头路径对照
curl -s -X POST http://localhost:8000/api/compare \
  -H 'Content-Type: application/json' \
  -d '{
        "headers_a": "Received: by mx.example; Tue, 23 Sep 2026 10:00:00 +0800",
        "headers_b": "Received: by mx.example; Tue, 23 Sep 2026 10:00:05 +0800"
      }'

# 接收链可信边界（trusted_hosts 为本组织接收服务器主机名数组）
curl -s -X POST http://localhost:8000/api/analyze/trust-boundary \
  -H 'Content-Type: application/json' \
  -d '{
        "headers": "Received: by edge.internal.corp; Thu, 24 Sep 2026 03:05:00 +0000\nReceived: from ext by gw2.internal.corp; Thu, 24 Sep 2026 03:04:00 +0000\nReceived: by relay.external; Thu, 24 Sep 2026 03:03:00 +0000",
        "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"]
      }'
```

`/api/analyze/share` 返回脱敏报告：主机名按投递顺序得到 `H1`、`H2`……，
IP 独立编号为 `IP1`、`IP2`……（别名仅在**本次请求内**稳定）。主机名比较
忽略大小写与末尾点，方括号 IP 字面量（`[10.0.0.1]`、`[IPv6:…]`）与解析出的
同一 IP 共享别名；同一值在 `node` / `from_host` / `delay_from` 中始终一致，
缺失身份、时间或耗时时对应字段为 `null`。输出字段为固定白名单，
**不含**原始 Received 文本、邮件摘要、Received `id`、`via` / `with` 等内容：

```json
{
  "host_aliases": ["H1", "H2"],
  "ip_aliases": ["IP1"],
  "path": [
    {
      "path_index": 1,
      "node": "H1",
      "from_host": "IP1",
      "ip": "IP1",
      "time_utc": "2026-09-23 02:02:00 UTC",
      "delay_from": null,
      "delay_seconds": null,
      "delay_human": null,
      "anomalies": []
    },
    {
      "path_index": 2,
      "node": "H2",
      "from_host": "H1",
      "ip": "IP1",
      "time_utc": "2026-09-23 02:03:00 UTC",
      "delay_from": "H1",
      "delay_seconds": 60.0,
      "delay_human": "1 分 0 秒",
      "anomalies": [
        {"level": "warn", "message": "……（仅通用解析说明，不含原文）……"}
      ]
    }
  ]
}
```

- 输入复用 `/api/analyze` 的同一套限制：`headers` 必须是字符串，
  空白输入、超过 `MAX_INPUT_KB` 上限或没有 `Received` 字段时返回 400；
- 页面 **“下载脱敏报告”** 按钮即以当前“头部 A”调用该接口，
  成功后把 JSON 保存为 `mailtrace-share-report.json`。

`/api/compare` 返回 `alignment.rows`（每行 `kind` 为 `common` / `added` / `missing`）
及 `common_count` / `added_count` / `missing_count` 统计；共有行内含
`delay_a_seconds`、`delay_b_seconds`、`delay_diff_seconds` 与可读形式。
任一侧没有 `Received` 字段时返回 400 及明确错误，例如：

```json
{"error": "B 侧头部中未找到 Received 字段，无法进行路径对照",
 "side_errors": {"b": "B 侧头部中未找到 Received 字段"}}
```

多封邮件慢段归因（接收 `headers` **字符串数组**，至少两项；每封邮件的完整
原始头部作为一个数组元素，分隔符切分在页面端完成）：

```bash
curl -s -X POST http://localhost:8000/api/batch-delays \
  -H 'Content-Type: application/json' \
  -d '{
        "headers": [
          "Received: by mid.example ...; ...\nReceived: by edge.example ...; ...",
          "Received: by mid.example ...; ...\nReceived: by edge.example ...; ...",
          "Received: by mid.example ...; ...\nReceived: by edge.example ...; ..."
        ]
      }'
```

返回结果（节选）：

```json
{
  "message_count": 3,
  "analyzed_count": 3,
  "message_errors": [],
  "segment_count": 2,
  "sample_count": 4,
  "excluded": {"invalid_time": 1, "backflow": 1, "identity_less": 0},
  "duplicate_collapsed": 0,
  "segments": [
    {
      "rank": 1,
      "from": {"node": "edge.example", "by_host": "edge.example", "ip": "203.0.113.50"},
      "to":   {"node": "mid.example",  "by_host": "mid.example",  "ip": "198.51.100.10"},
      "sample_count": 3,
      "median_seconds": 150.0, "median_human": "2 分 30 秒",
      "max_seconds": 600.0,    "max_human": "10 分 0 秒"
    }
  ]
}
```

- `segments` 已按**中位耗时从慢到快**排序；`from` / `to` 分别是该相邻区段的上游、
  下游节点（`ip` 为该节点在其上游 `Received` 中记录的对端 IP，可能为 `null`）；
- `excluded.invalid_time` = 因本节点或上游时间缺失 / 无法解析而排除的区段数，
  `excluded.backflow` = 因负耗时（时间倒灌）而排除的区段数，
  `excluded.identity_less` = 任一端无 by/IP 身份、未参与合并的区段数；
- `duplicate_collapsed` = 同一封邮件内同键区段重复出现、按“取最大有效非负耗时”
  归并掉的额外出现次数；
- 某封邮件没有 `Received` 字段时记入 `message_errors`（含其在数组中的序号），
  其余邮件继续分析；所有邮件都没有 `Received`、数组少于两项、元素不是字符串
  或存在空白项时返回 400。

ARC 链结构检查（本地启动后地址为 `http://localhost:8000/api/arc/check`，
端口随 `HOST_PORT` 变化，见下文“访问端口”）：

```bash
curl -s -X POST http://localhost:8000/api/arc/check \
  -H 'Content-Type: application/json' \
  -d '{"headers": "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=...\nARC-Message-Signature: i=1; ...\nARC-Authentication-Results: i=1; mx.example.com; spf=pass ..."}'
```

返回结构与页面共用同一结果（`status` 为 `pass` / `fail` / `none` 之一，
`none` 表示“无 ARC 链”，不判定通过）：

```json
{
  "status": "fail",
  "status_label": "ARC 链结构异常",
  "arc_field_count": 5,
  "instance_count": 1,
  "error_count": 2,
  "issues": [
    {"instance": 1, "field": "ARC-Authentication-Results",
     "code": "missing_field",
     "message": "实例 i=1 缺少 ARC-Authentication-Results 字段（每实例须三类字段各一条）"},
    {"instance": 2, "field": null, "code": "gap",
     "message": "实例号 i=2 缺失：实例号必须从 1 开始连续，不允许跳号"}
  ],
  "instances": [
    {"i": 1, "ok": false,
     "seal": {"present": true, "count": 1, "cv": "none",
              "cv_expected": "none", "cv_ok": true, "raw": "ARC-Seal: i=1; ..."},
     "message_signature": {"present": true, "count": 1, "raw": "..."},
     "authentication_results": {"present": false, "count": 0, "raw": null}}
  ],
  "invalid_fields": [
    {"field": "ARC-Seal", "i_raw": "abc", "raw": "...", "message": "..."}
  ],
  "numbering": {"ok": false, "found": [1, 3], "missing": [2]}
}
```

- `issues` 逐项定位问题：`code` 为 `missing_i` / `invalid_i`（非法 i）、
  `duplicate_field` / `missing_field`（字段重复 / 缺失）、`gap`（跳号）、
  `cv_missing` / `cv_bad`（cv 异常），并给出实例号与字段名；
- `invalid_fields` 列出因 `i` 缺失或非法而无法归组的 ARC 字段原文；
- 输入限制与其他接口一致：`headers` 必须是字符串，空白输入或超过
  `MAX_INPUT_KB` 上限返回 400；头部中完全没有 ARC 字段时返回 200 且
  `status` 为 `none`。

DKIM 头字段覆盖审计（本地启动后地址为 `http://localhost:8000/api/dkim/coverage`，
端口随 `HOST_PORT` 变化，见下文“访问端口”）：

```bash
curl -s -X POST http://localhost:8000/api/dkim/coverage \
  -H 'Content-Type: application/json' \
  -d '{"headers": "DKIM-Signature: v=1; d=example.com; s=sel; h=From:To:Subject:Date; b=...\nFrom: ...\nTo: ...\nSubject: ...\nDate: ..."}'
```

返回结构与页面共用同一结果（`status` 为 `ok` / `anomaly` / `none` 之一，
`none` 表示“无 DKIM 签名”，不判定通过；`anomaly` 仅由缺失 / 空 `h=`
（及 `h=` 标签重复）触发，未匹配项本身不算异常）：

```json
{
  "status": "anomaly",
  "status_label": "DKIM 字段覆盖异常",
  "signature_count": 2,
  "anomaly_count": 1,
  "header_field_count": 10,
  "signatures": [
    {
      "index": 1,
      "status": "ok",
      "field_position": 1,
      "domain": "forwarder.example",
      "selector": "sel2",
      "h_present": true,
      "h_count": 6,
      "matched_count": 5,
      "unmatched_count": 1,
      "issues": [],
      "h_results": [
        {"list_index": 1, "name": "Received", "matched": true,
         "field_position": 4, "value": "from relay... by mx.forwarder..."},
        {"list_index": 6, "name": "X-Missing", "matched": false,
         "field_position": null, "value": null}
      ],
      "unmatched": [
        {"list_index": 6, "name": "X-Missing",
         "message": "头部中没有未被本签名使用的 X-Missing 字段"}
      ],
      "uncovered_core": [
        {"field": "To", "position": 7, "value": "extra-injected@evil.example"},
        {"field": "Date", "position": 5, "value": "Thu, 24 Sep 2026 ..."}
      ],
      "raw": "DKIM-Signature: ..."
    }
  ],
  "notice": "结果仅表示 DKIM-Signature 的 h= 列表覆盖了哪些实际头字段，不校验也不宣称签名真伪（未验证 b= 签名值、域名与密钥）。"
}
```

- 匹配口径（RFC 6376 §3.7 / §5.4.2）：每条签名独立处理，自左向右遍历
  `h=` 列表，每项自头部**底部向上**取第一个同名且尚未被本签名使用的实际
  字段；因此 `h=` 中重复出现的字段名会依次命中同名头从最新到最旧的不同
  副本，**不会按集合合并**。当前被审计的 `DKIM-Signature` 自身不参与
  匹配（对他人签名做 countersignature 时，其他 `DKIM-Signature` 照常
  命中）。`field_position` 为字段在头部中出现的序号（从 1 开始）。
- `issues`（每条签名内）的 `code` 为 `missing_h` / `empty_h` /
  `duplicate_h`；`unmatched` 列出未命中的 `h=` 项（含列表序号），
  `uncovered_core` 列出 `From` / `Subject` / `To` / `Date` 中未被该
  签名覆盖的实际字段副本及位置。
- 输入限制与其他接口一致：`headers` 必须是字符串，空白输入或超过
  `MAX_INPUT_KB` 上限返回 400；头部中完全没有 `DKIM-Signature` 时返回
  200 且 `status` 为 `none`。

接收链可信边界（本地启动后地址为
`http://localhost:8000/api/analyze/trust-boundary`，端口随 `HOST_PORT`
变化，见下文“访问端口”）：

```bash
curl -s -X POST http://localhost:8000/api/analyze/trust-boundary \
  -H 'Content-Type: application/json' \
  -d '{
        "headers": "Received: from gw2 ... by edge.internal.corp; ...\nReceived: from ext ... by gw2.internal.corp; ...\nReceived: ... by relay.external; ...",
        "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"]
      }'
```

`trusted_hosts` 既可以是主机名**字符串数组**（推荐），也可以是每行一个
主机名的字符串（表单提交即此形式，同时兼容逗号 / 空格分隔）；名单项忽略
大小写与末尾点并自动去重。返回结构与页面共用同一结果：

```json
{
  "status": "established",
  "status_label": "可信链已建立",
  "message": "自顶端连续 2 跳命中本组织名单；可信边界位于头部自上而下第 3 跳……",
  "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"],
  "hop_count": 3,
  "trusted_count": 2,
  "untrusted_count": 1,
  "boundary": {"top_index": 3, "by_host": "relay.external",
               "reason": "not_listed", "reason_label": "by 主机不在本组织名单内"},
  "last_trusted_hop": {"top_index": 2, "by_host": "gw2.internal.corp",
                       "from_host": "gateway.partner.example",
                       "ip": "203.0.113.55", "time_utc": "2026-09-24 03:04:30 UTC"},
  "hops": [
    {"top_index": 1, "path_index": 3, "trusted": true, "is_boundary": false,
     "beyond_boundary": false, "reentry_listed": false, "has_by": true,
     "by_listed": true, "by_host": "edge.internal.corp", "...": "..."},
    {"top_index": 2, "path_index": 2, "trusted": true, "...": "..."},
    {"top_index": 3, "path_index": 1, "trusted": false, "is_boundary": true,
     "by_listed": false, "reentry_listed": false, "...": "..."}
  ]
}
```

- 检查顺序为头部**书写顺序**（`top_index` 从 1 开始，1 = 最上方、最靠近
  收件方的一条）；`path_index` 为投递方向（发件方 → 收件方）序号，仅作
  交叉参照。仅自顶端**连续命中**名单的跳 `trusted=true`；首个未命中
  （`reason: "not_listed"`）或缺少 `by`（`reason: "missing_by"`）的跳
  即边界并标记 `is_boundary=true`。
- 边界之后的所有跳 `beyond_boundary=true` 且 `trusted=false`；其中
  `by` 再次命中名单者额外标记 `reentry_listed=true`（**不会重新接入**，
  常见于外部主机冒用本组织主机名、退信后重新注入等情形）。
- `last_trusted_hop` 是连续可信前缀的最外侧一跳，其 `from_host` / `ip`
  即本组织边缘接收服务器看到的**外部交接点**；没有任何可信跳时为 `null`。
- 全部跳均命中时 `boundary` 为 `null`（整段链路都在可信边界内）。
- 状态码约定：
  - `established`（200）：自顶端至少一跳命中（可能在中间到达边界）；
  - `untrusted_top`（200）：顶端第 1 跳即未命中 / 缺少 `by`，
    **无法建立可信链**；
  - `no_received`（200）：头部中没有 `Received` 字段，
    **无法建立可信链**；
  - `trusted_hosts` 为空名单、类型错误、`headers` 非字符串或空白、
    超过 `MAX_INPUT_KB` 上限时返回 **400** 及 `error` 说明。

认证结果来源（本地启动后地址为
`http://localhost:8000/api/analyze/auth-results`，端口随 `HOST_PORT`
变化，见下文“访问端口”）：

```bash
curl -s -X POST http://localhost:8000/api/analyze/auth-results \
  -H 'Content-Type: application/json' \
  -d '{
        "headers": "Authentication-Results: edge.internal.corp; spf=pass smtp.mailfrom=x.example; dkim=pass header.d=x.example; dmarc=pass header.from=x.example\nReceived: from gw2 ... by edge.internal.corp; ...\nReceived: from ext ... by gw2.internal.corp; ...",
        "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"]
      }'
```

输入与 `/api/analyze/trust-boundary` 相同（`trusted_hosts` 支持字符串数组
或每行一个主机名的字符串）。返回结构与页面共用同一结果：

```json
{
  "status": "established",
  "status_label": "可信链已建立",
  "message": "共 2 条 Authentication-Results 字段，其中 1 条归属本组织……",
  "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"],
  "hop_count": 3,
  "trusted_count": 2,
  "boundary": {"top_index": 3, "by_host": "relay.external", "...": "..."},
  "ar_count": 2,
  "own_count": 1,
  "no_org_claims": false,
  "no_org_reason": null,
  "auth_summary": [
    {"method": "spf", "result": "pass", "field_index": 1, "hop_top_index": 1},
    {"method": "dkim", "result": "pass", "field_index": 1, "hop_top_index": 1},
    {"method": "dmarc", "result": "pass", "field_index": 1, "hop_top_index": 1}
  ],
  "results": [
    {"index": 1, "field_position": 1, "authserv_id": "edge.internal.corp",
     "status": "own", "status_label": "本组织声明",
     "hop_top_index": 1, "hop_by_host": "edge.internal.corp",
     "methods": [{"method": "spf", "result": "pass"}, "..."],
     "detail": "……", "raw": "Authentication-Results: ..."},
    {"index": 2, "authserv_id": "relay.external",
     "status": "beyond_boundary", "status_label": "越过边界",
     "hop_top_index": 3, "hop_by_host": "relay.external",
     "methods": [], "...": "..."}
  ]
}
```

- 归属口径：每条 `Authentication-Results` 归属到其后**紧邻的
  `Received`**（沿头部向下第一条，两者之间不得有另一条 `Received`）；
  仅当该跳属于自顶端连续可信前缀、且 `authserv-id` 与该跳 `by` 主机一致
  （忽略大小写与末尾点）时 `status` 为 `own`（本组织声明）。其余取值：
  `no_hop`（无对应跳：其后没有任何 `Received`）、`beyond_boundary`
  （越过边界：对应跳不在连续可信前缀内，含边界之后 by 再次命中名单的
  伪造跳）、`identity_mismatch`（身份不符：对应跳可信但 authserv-id
  缺失 / 为 `none` / 与 by 主机不一致）。
- `auth_summary` 汇总所有本组织声明中的 `spf` / `dkim` / `dmarc` 结果词，
  **按原文顺序、保留重复声明**（同一方法出现多次不去重）；
  `field_index` 指回第几条 AR 字段。非本组织声明的字段不提取、不汇总。
- `no_org_claims=true` 时页面与 JSON 明确表示**无本组织声明**，原因见
  `no_org_reason`：`no_trusted_prefix`（无法建立连续可信前缀）、
  `no_auth_results`（头部没有 Authentication-Results 字段）、
  `none_attributed`（有字段但无一归属本组织）。
- 状态码约定与可信边界一致：`status` 复用 `established` /
  `untrusted_top` / `no_received`（均为 200）；空名单、类型错误、
  空白头部或超过 `MAX_INPUT_KB` 上限返回 **400** 及 `error` 说明。

发件域对齐审计（本地启动后地址为
`http://localhost:8000/api/analyze/sender-alignment`，端口随 `HOST_PORT`
变化，见下文“访问端口”）：

```bash
curl -s -X POST http://localhost:8000/api/analyze/sender-alignment \
  -H 'Content-Type: application/json' \
  -d '{
        "headers": "Authentication-Results: edge.internal.corp; spf=pass smtp.mailfrom=news@mail.partner.example; dkim=pass header.d=mail.partner.example\nReceived: from gw2 ... by edge.internal.corp; ...\nReceived: from ext ... by gw2.internal.corp; ...\nFrom: News <news@mail.partner.example>",
        "trusted_hosts": ["edge.internal.corp", "gw2.internal.corp"],
        "org_domain": "partner.example",
        "mode": "strict"
      }'
```

- `mode`：`strict`（严格，默认）或 `relaxed`（宽松）；`org_domain`
  为发件组织域，**宽松模式必填**（严格模式可不填，不参与比较）。
- 返回结构与页面共用同一结果：`status` 三选一——`aligned`
  （**有对齐证据**：至少一条本组织通过声明对齐）、`not_aligned`
  （**未见对齐证据**：有可用通过声明但均不对齐）、`insufficient`
  （**证据不足**，原因见 `reason`：`from_missing` / `from_multiple_fields` /
  `from_multiple_addresses` / `from_no_address` / `from_no_domain` /
  `from_invalid_domain` / `no_own_claims` / `no_pass_claims` /
  `no_usable_claims`）。

```json
{
  "status": "aligned",
  "status_label": "有对齐证据",
  "reason": null,
  "message": "有对齐证据：1 条本组织通过声明的身份域与 From 域 mail.partner.example 对齐（严格模式）……",
  "mode": "strict",
  "mode_label": "严格模式",
  "org_domain": "partner.example",
  "from": {"status": "ok", "status_label": "已解析唯一 From 域",
           "domain": "mail.partner.example",
           "address": "news@mail.partner.example",
           "field_count": 1, "field_positions": [10]},
  "trust_status": "established",
  "ar_count": 2, "own_count": 1,
  "claim_count": 2, "pass_claim_count": 2,
  "usable_claim_count": 2, "aligned_count": 1,
  "claims": [
    {"index": 1, "method": "spf", "result": "pass",
     "field_index": 1, "field_position": 1,
     "hop_top_index": 1, "hop_by_host": "edge.internal.corp",
     "identity_prop": "smtp.mailfrom",
     "identity_raw": "news@mail.partner.example",
     "identity_domain": "mail.partner.example",
     "status": "aligned", "status_label": "对齐",
     "detail": "身份域 mail.partner.example 与 From 域 mail.partner.example 完全相同……"}
  ],
  "notice": "对齐结论仅采纳归属本组织可信前缀的 Authentication-Results 声明……"
}
```

- `claims` 逐条列出本组织声明中的 `spf` / `dkim` 声明：方法、结果词、
  声明字段位置（`field_index` = 第几条 AR 字段，`field_position` =
  头部第几个字段）、接收跳（`hop_top_index`，头部自上而下）、身份域
  （`identity_prop` 原始属性与提取出的 `identity_domain`）及比较结果
  （`status`：`aligned` / `not_aligned` / `no_identity`（pass 但缺身份域）/
  `not_pass`（非 pass，不参与）/ `uncomparable`（From 域不可用））。
- 只采纳归属本组织可信前缀的 AR 字段（复用 `/api/analyze/auth-results`
  的归属判定）；`from.status` 非 `ok`（重复 From、多地址、缺地址 /
  缺域 / 域非法）时不静默择一，总体结论为 `insufficient`。
- 状态码约定：空名单、非法 `mode`、宽松模式缺 `org_domain`、组织域非法、
  空白头部或超过 `MAX_INPUT_KB` 上限返回 **400**；三种对齐结论均为 200。

健康检查：`GET http://localhost:8000/healthz`。

---

## 排序原理（为什么要反转）

邮件每经过一台服务器，该服务器就把自己的 `Received` 字段**追加到头部最前面**。
因此头部文本里第一条 `Received` 是最后一跳（最靠近收件方），最后一条才是第一跳。
本工具按这一“嵌套结构”将 `Received` **反转**后呈现，得到真实投递顺序，
再用时间戳校验该顺序并计算相邻耗时。当解析出的时间出现倒挂（时钟偏差或伪造）时，会明确告警。

---

## 配置（环境变量）

| 变量 | 默认值 | 作用范围 | 说明 |
| --- | --- | --- | --- |
| `HOST_PORT` | `8000` | Compose | 宿主机映射端口（容器内服务固定监听 8000） |
| `APP_PORT` | `8000` | 容器/本地 | 容器内 gunicorn 绑定端口；改它需同步调整端口映射 |
| `APP_HOST` | `0.0.0.0` | 本地 | 直接用 Flask 开发服务器运行时的监听地址 |
| `MAX_INPUT_KB` | `256` | 容器/本地 | 单次粘贴头部的大小上限（KB），超出返回错误 |
| `SKIP_STARTUP_INSTALL` | `0` | 容器 | 设为 `1` 跳过容器启动时的 `pip install`，直接用镜像内依赖 |

### 访问端口

- Compose 默认把宿主机 **8000** 端口映射到容器 8000。
- 想换宿主机访问端口，在项目根目录创建 `.env`（或先导出环境变量再 `up`）：

```bash
echo "HOST_PORT=9000" > .env
docker compose up -d --build
# 访问 http://localhost:9000
```

也可以在运行时直接覆盖，例如：

```bash
docker run --rm -e MAX_INPUT_KB=512 -p 8080:8000 mailtrace
# 访问 http://localhost:8080
```

---

## 本地开发（不使用容器）

需要 Python 3.11+。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python wsgi.py            # Flask 开发服务器，默认 http://localhost:8000
# 或
gunicorn -b 0.0.0.0:8000 wsgi:app
```

运行解析器测试（**仅需标准库，无需安装 Flask**）：

```bash
python -m unittest discover -s tests -v
```

---

## 项目结构

```
.
├── app/                    # Flask 应用（路由、模板）
│   ├── __init__.py         # create_app()：页面 + 对照 + JSON API + 健康检查
│   └── templates/index.html
├── mailtrace/              # 纯标准库解析核心（可独立复用）
│   └── parsing/
│       ├── parser.py       # 折行展开、时间解析、路径排序、耗时与异常
│       ├── compare.py      # 双邮件头对照：保序全局对齐、耗时差值
│       ├── batch.py        # 多封慢段归因：相邻节点对聚合、中位/最大耗时、排除计数
│       ├── share.py        # 单封脱敏分享：H1/IP1 别名化、白名单报告
│       ├── arc.py          # ARC 链结构检查：i 标签归组、字段齐全性、连续编号、cv 校验
│       ├── dkim.py         # DKIM h= 头字段覆盖审计：逐条签名、自底部向上匹配、重复字段不合并
│       ├── trust.py        # 接收链可信边界：自顶端连续 by 命中、边界位置、外部交接点
│       ├── authres.py      # 认证结果来源：AR 归属紧邻 Received、可信前缀 + authserv-id 判定
│       ├── align.py        # 发件域对齐审计：唯一 From 域、spf/dkim pass 身份域、严格/宽松比较
│       └── sample.py       # 页面“填入示例”数据（A / B、批量三份、ARC、DKIM、可信边界、认证结果来源及发件域对齐示例）
├── wsgi.py                 # gunicorn / flask 启动入口
├── entrypoint.sh           # 容器启动时安装依赖并启动 gunicorn
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── tests/                  # 解析核心、对照、脱敏、慢段归因、ARC 链、DKIM 覆盖、可信边界、认证结果来源与发件域对齐单元测试
    ├── test_parser.py
    ├── test_compare.py
    ├── test_share.py
    ├── test_batch.py
    ├── test_arc.py
    ├── test_dkim.py
    ├── test_trust.py
    ├── test_authres.py
    └── test_align.py
```

## 安全与隐私

应用只在本地/你的服务器内解析粘贴内容，不向任何外部服务发送邮件头；
请仍按敏感信息对待原始头部（其中可能含内网主机名与 IP）。
需要外发排查结果时，使用**“下载脱敏报告”**（`/api/analyze/share`）：
报告只含投递顺序、`H1` / `IP1` 等本次请求内的匿名别名、UTC 时间、相邻耗时
与通用异常说明，原始头部、邮件摘要与 Received ID 等均被排除。
