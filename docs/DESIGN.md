# 远程脚本执行引擎设计

## 目标

实现一个轻量的远程脚本执行引擎，优先考虑 Go 或 Rust，运行环境覆盖 Unix/macOS 宿主机与容器。第一阶段聚焦局域网；执行端 Agent 尽量免配置、可靠稳定，客户端负责任务发起、输出查看和个性化处理。当前仓库实现 Go Agent 核心、QUIC 服务、mDNS 发布/发现和通用线协议；客户端 UI、peek 缓存与个性化处理由另一个客户端实现。

## 原始需求

- 宿主机和容器都能运行或接入执行端；本机宿主与容器之间可通过本机通信互联。
- 节点之间可发现并通信，支持 P2P；减少中心控制面依赖。第一阶段仅做局域网，跨网能力以后再讨论。
- 优先 Go 或 Rust；通信开销小、协议通用。
- 支持可选鉴权，并防止不同机器间的网络中间人攻击。
- 远程执行完整命令字符串，shell 由执行器指定并解析。
- 支持 stdout、stderr 分别查看，也支持按输出观察顺序混合查看。
- 支持多次运行并发；每次运行彼此独立，且一次运行只包含一条 shell 命令。
- 每条命令都必须指定工作目录，并可指定环境变量、stdin 和超时。运行 ID 由 Agent 生成并下发，客户端后续查询/取消都用该 ID。
- 超时默认 5 分钟，最大 1 小时；支持取消，并返回退出码。
- 支持在任务结束前查看当前状态和已有输出（peek）。peek 与输出展示由客户端实现。
- 不设 Agent 侧输出量上限；脚本/客户端自行用 tail、grep 等方式控制输出。Agent 负责连接和执行，客户端负责缓存、处理和定制。
- 不缓存断线后的结果。默认断线即终止任务。
- 正常结束、非零退出、取消或超时后，清理命令及其受管后代：先终止，等待最多 10 秒，再强杀。
- 不增加外部进程监督；Agent 被强杀或后代脱离受管进程组后遗留进程，接受不处理。

## 方案分析

### 节点与发现

不设置必需的中心控制面。第一阶段在局域网用 mDNS 发现执行端；也可支持显式地址作为诊断或回退方式。跨网 NAT 穿透、协调节点和 relay 不纳入第一阶段。

宿主机与容器属于同机通信时，优先通过 Unix domain socket 接入宿主 Agent，并用 socket 文件权限及可用的本机进程凭据限制访问。不要仅凭 IP 地址或 loopback 判断是否同机。

### 通信与运行模型

Agent 使用 QUIC + TLS 1.3。一个连接可复用多个双向 stream；每次运行独立使用一个 stream，同一客户端可并发提交多次运行。一次运行就是一条 shell 命令，不存在任务级多命令编排——需要多条命令时由调用方自行发起多次运行。运行结束后关闭对应 stream；最后一个活动 stream 结束后，Agent 等待约 200 ms 并关闭连接。新连接若 10 秒内未打开 stream 也会关闭；活动命令期间有 QUIC keepalive 支持长时间无输出的运行。

stdout 与 stderr 分开采集和传输。每个输出块携带流类型和递增序号，客户端可按流查看，或按 Agent 观察到的序号合并。两个 OS 管道不能提供进程层面的全局真实写入顺序，因此混合顺序的定义是 Agent 采集观察顺序。

Agent 不缓存断线后的输出；输出实时流式发送，使用有界内存块和传输层背压，不设累计输出字节上限。客户端断开默认取消对应运行。取消请求和断线均触发受管命令组清理；因断线无法保证客户端收到最终状态，客户端不应假定运行结果可重取。

### 身份与鉴权

Agent 可选验证客户端身份：Agent 二进制内嵌一个 Ed25519 客户端公钥；客户端用对应私钥生成 TLS 客户端证书。Agent 在 TLS 校验公钥，并在任务请求中校验 `client_id` 等于该公钥 SHA-256 指纹。客户端私钥由 `keygen` 命令生成并以仅用户可读权限保存；私钥不编入二进制。鉴权默认关闭必须显式传 `--allow-unauthenticated`；启用鉴权时通过构建参数嵌入公钥。

Agent 首次运行自动生成并持久化服务端 Ed25519 身份，ID 是公钥指纹，并通过 mDNS 公布。按用户明确选择，客户端**不验证执行端证书/身份**。因此客户端到 Agent 的 TLS 连接并不具备对端认证：恶意假 Agent 或中间人仍可能诱骗客户端提交命令、读取命令内容或伪造响应。客户端公钥认证只限制谁能让真实 Agent 执行命令，不能替代客户端验证服务端身份；这是已接受的安全限制，不应宣称完整防 MITM。

### shell 与命令

仅支持 bash、fish、zsh；执行端只公布本机确实可用的 shell。请求必须明确指定 shell 和完整命令字符串，不根据启动 Agent 的默认 shell 猜测。不同 shell 语法不兼容，客户端需要按指定 shell 组织命令。

每条命令单独具有必填 cwd、环境变量、stdin 和超时；shell 只能是本机实际存在的 bash、fish 或 zsh。环境变量基于 Agent 进程环境合并覆盖。超时省略或为 0 时按 5 分钟处理，最大 1 小时。运行结果只描述这一条命令。

### 进程清理

Agent 为命令创建受管进程组/等效运行边界。取消、超时、断线取消及命令结束时，先请求终止受管进程组，等待最多 10 秒，再强杀仍存活成员并回收直接子进程及管道。

不承诺对主动脱离进程组、daemonize 或 Agent 被 SIGKILL 等情况作外部兜底；用户已明确接受不使用外部监督，可能遗留此类进程。Unix/macOS 的具体进程组实现与平台差异需分别验证。

## 当前技术实现

1. **语言与依赖**：Go；QUIC 使用 `github.com/quic-go/quic-go`，mDNS 使用 `github.com/grandcat/zeroconf`。
2. **发现**：发布/发现 `_remote-shell._udp` DNS-SD 服务，TXT 公布协议版本、Agent 稳定 ID 和是否要求客户端鉴权。发现信息不作为信任凭据。
   mDNS 注册失败（如容器内无多播）只记录日志并继续服务，不阻止 Agent 启动。
3. **线协议**：ALPN 为 `remote-shell/1`。每帧为 1 字节类型 + 4 字节大端长度 + payload；控制消息用 JSON，最大 4 MiB；stdout/stderr 用二进制帧避免 Base64 膨胀。运行请求的 stdin 与其余控制字段同帧 JSON 传输，受同一 4 MiB 上限约束。请求使用 `timeout_ms`，省略/0 表示默认值。单次运行的 stream 首帧为运行请求（只含一条命令），Agent 随后先回一帧运行 ID，再回输出块与结束结果；客户端取消即关闭 stream 写方向。Agent 先读取首帧再占用全局 stream 配额；读首帧超时 5 秒，未打开运行流（stream）的连接 10 秒后关闭，最后一次运行结束后的空闲连接约 200 ms 后关闭。配额满时请求排队：stream 槽最多等 50 ms、run 槽最多等 100 ms，超时才返回错误帧。单连接获得的 QUIC stream 信用额度等于 stream 上限，因此 stream 槽排队只在多个连接之间发生。
4. **输出排序**：输出帧包含运行内递增 `seq`、stdout/stderr 类型和原始字节。该序号代表 Agent 收集两个管道时的观察顺序，不承诺进程跨管道的绝对写入时序。
5. **调度限制**：默认最多 64 个并发运行、128 个并发 stream；serve 参数（`--max-runs`/`--max-streams`）可调整，硬上限分别为 1024 和 4096。建议保持 stream 上限大于 run 上限：等待 run 槽的请求会短暂占用 stream 槽，两者接近时更容易触发 50 ms 排队超时。命令输出实时转发，单块约 32 KiB，不累计缓存；下游慢时依靠管道和 QUIC 流控形成背压。
6. **鉴权与身份**：使用 `make keygen`（即 `scripts/build.fish keygen`）生成客户端密钥，默认保存到 `keys/client.key`（权限 `0600`，由 `.gitignore` 排除），同时将公钥记录在 `keys/client-key-info`。`make build` 生成 macOS arm64 与 Linux amd64 两个最小化构建，并将该公钥编入二进制；构建前会用 `remote-shell pubkey` 校验私钥与记录的公钥一致，不一致直接失败。客户端私钥可通过 `identity.LoadClientPrivateKey` 读取。Agent 的服务端身份自动生成并稳定保存，但客户端不验证它。
7. **清理**：每条命令放入独立进程组。取消或超时后先 TERM，等待最多 10 秒，再 KILL。shell 自身退出（含非零退出）后，若组内仍有后代，立即 TERM，最多等 5 秒输出排空后 KILL，避免正常结束的运行被后台进程拖住 10 秒；超时仍未排空则关闭 agent 自身读端，保证运行不会永久卡住。Agent 退出时关闭连接并等待受管运行清理。无外部 supervisor；Agent 被 SIGKILL 或后代脱离进程组造成的残留已接受。
8. **运行**：`remote-shell serve` 启动执行端；鉴权关闭需显式 `--allow-unauthenticated`。默认 mDNS 广播，也可用 `--no-discovery` 关闭。根命令和子命令均支持 `-h`、`--help`。构建逻辑在 `scripts/build.fish`：`GO`、`CGO_ENABLED`、`GOFLAGS`、`LDFLAGS`、`KEY_DIR`、`OUT_DIR` 通过环境变量共享，Makefile 只是转发这几个变量的薄封装。
9. **MCP 桥接**：`remote-shell mcp` 把执行端暴露为 MCP 工具，支持 `--transport stdio`（默认）与 `--transport http`（streamable HTTP，端点 `/mcp`，默认只绑 `127.0.0.1:8765`，可用 `--auth-token` 要求 Bearer）。工具集：`discover_nodes`（mDNS 列节点）、`list_shells`（Agent 上可用的 shell）、`shell`（跑一条命令，可 `background`）、`shell_status`、`shell_output`（按 `all`/`stdout`/`stderr` 视图分页读取）、`shell_cancel`、`list_runs`。运行 ID 由 Agent 生成并作为唯一查询键，桥接不再虚构第二套 ID。每次 `shell` 单独拨一条 QUIC 连接，不连接池复用；运行结束或取消后连接即关闭，Agent 侧按断线语义清理。输出在桥接进程内按到达顺序缓存，超过 `--max-output-bytes`（默认 8 MiB）时丢弃最旧字节并用 `trimmed_bytes`/`next_offset` 如实报告；前台调用返回全部保留输出，后台运行通过 `shell_status`/`shell_output` 轮询。stdio 模式下日志只走 stderr，stdout 保持纯协议通道；`--node` 为默认目标，缺省时可用 `node` 参数传 `host:port` 或 `discover_nodes` 得到的节点 ID。非零退出码按正常结果返回，只有传输失败、取消、超时才标记为工具错误。
未给 `node` 且没有 `--node` 时，桥接自动使用 mDNS 发现的唯一 Agent。发现结果一经找到就缓存，不按时间过期；只有连接失败时才丢弃缓存并重新搜索、重试一次，找到/丢弃都会记一行日志。每个节点还会记住上次连通的地址并优先尝试；发现到多个 Agent 时报错并列出候选，不做猜测。
支持的协议版本限定为 `2026-07-28` 与 `2025-11-25`（`ServerOptions.SupportedProtocolVersions`），更旧的版本一律拒绝，避免在未验证的语义下运行。
HTTP 传输采用 stateless 模式：无需 initialize 握手、不下发 Mcp-Session-Id，因此 curl 或一次性脚本可直接调用，也能使用当前协议版本（2026-07-28，需带 Mcp-Method/Mcp-Name 及 _meta 路由信息）；旧版本（2025-11-25 及更早）同样可用。
（`--listen` 与 `--auth-token` 只对 HTTP 有意义：未显式指定 `--transport` 时它们隐含选择 HTTP，显式写 `--transport stdio` 又带这两个参数会直接报错。）
Agent 日志：每个入站请求分配单调递增的 req ID，请求开始时记 `event=start`（kind=shell|shells、run、shell、cwd、timeout、client、remote），结束时记 `event=done`（state=succeeded|failed|cancelled|timed_out、duration、exit、stdout/stderr 字节数）；日志读取方按 req ID 配对两条记录。

## 已知限制与后续工作

- 当前实现不含独立客户端 UI/peek 缓存；客户端应在接收实时事件时自行缓存和呈现。
- 未实现宿主机与容器的 Unix socket 本机接入；容器当前需通过可达的 UDP/QUIC 地址接入 Agent，并满足其网络配置。
- 客户端不验证服务端身份，因此不满足客户端方向的 MITM 防护；这是用户明确选择的行为。
- 获得授权的客户端可在 Agent 当前操作系统用户权限下执行任意 shell 命令；Agent 不提供沙箱或 CPU/内存限额。鉴权关闭时，同一网络中可连接的节点都可提交命令。
- 进程组无法覆盖主动脱离进程组的后代，也无法在 Agent 被 SIGKILL 后执行清理；不使用外部 supervisor。
- 第一阶段仅支持局域网 mDNS，不实现跨网 rendezvous、NAT 打洞或 relay。
- 写输出帧没有写超时：客户端停止读取时，运行与 stream 槽会被背压长期占用；这是「只靠背压、不设输出上限」的直接代价。
- 收包按帧头声明长度一次性分配，最坏为 4 MiB × 并发 stream 上限；未对 stdin 单独设更小上限。
- 命令被外部信号终止且没有取消/超时参与时，`exit_code` 为 -1、无 cancelled/timed_out 标志且 `error` 为空，客户端需按此约定识别信号致死；若同时有取消或超时，则以对应标志为准。
- 运行核心目前用 Unix 进程组接口实现；Linux/macOS 为主要目标，其他 Unix 目标需构建验证。
- MCP 桥接每次 `shell` 都重新拨号，未做连接复用；局域网下握手开销可接受，广域场景会明显。
- MCP 侧输出缓存有上限：超出 `--max-output-bytes` 的旧字节被丢弃，前台结果只能看到保留的尾部，需用 `shell_output` 分页读取剩余部分。
- MCP 的 HTTP 传输默认只监听回环地址；监听非回环地址时应配置 `--auth-token`，否则同网段任何人都能提交命令。
- 一次运行只有一条命令；多条命令由模型发起多次 `shell` 调用，桥接与 Agent 都不做命令编排。
