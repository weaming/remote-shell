# remote-shell

局域网内的远程脚本执行引擎：一个 Go 编写的 Agent 跑 shell 命令，客户端通过 QUIC 提交并实时接收输出；另带一个 MCP 桥接，让模型直接调用。

## 组成

| 目录 | 作用 |
|---|---|
| `agent/` | QUIC 监听、mDNS 广播、鉴权、并发配额、运行日志 |
| `execution/` | 单条命令的进程组执行、取消/超时清理、结果归类 |
| `protocol/` | 帧协议：请求、运行 ID 通知、输出、结果 |
| `discovery/` | mDNS 发布与发现 |
| `client/` | QUIC 客户端（拨号、运行、取消） |
| `mcpserver/` | MCP 桥接：工具集与 stdio / streamable HTTP 传输 |
| `cmd/remote-shell/` | `serve`、`mcp`、`keygen`、`pubkey` 四个子命令 |

## 快速开始

```fish
make keygen    # 生成 keys/client.key（0600）与 keys/client-key-info
make build     # 构建 dist/remote-shell-{darwin-arm64,linux-amd64}，公钥编入二进制

./dist/remote-shell-darwin-arm64 serve --name build-box   # 默认 UDP :42424 + mDNS
./dist/remote-shell-darwin-arm64 mcp                     # stdio；加 --listen 127.0.0.1:8765 即切到 HTTP（/mcp）
```

Agent 首次启动会在状态目录（macOS `~/Library/Application Support/remote-shell/`）生成并复用 `identity.key`；`node-…` 是它的公钥指纹。

## MCP 工具

| 工具 | 说明 |
|---|---|
| `shell` | 跑一条命令；返回 Agent 分配的 run ID（96 bit 随机） |
| `shell_status` / `shell_output` | 按 run ID 查状态、按 `all`/`stdout`/`stderr` 分页读输出 |
| `shell_cancel` | 按 run ID 取消（TERM → 10s → KILL） |
| `list_runs` | 桥接记得的运行 |
| `list_shells` / `discover_nodes` | 目标机可用 shell / 局域网 Agent |

`node` 可填 `host:port`、`--name`、主机名或 node ID；同机时优先走 `127.0.0.1`。`cwd` 支持 `~/子路径`，由 Agent 按其自身用户展开。

## 关键约定

- 一次运行只有一条命令，没有多命令编排；需要多条就调用多次。
- 输出实时流式，不落盘；授权客户端在 Agent 用户权限下执行任意命令，没有沙箱。
- 客户端校验不了服务端身份（已接受的设计取舍），只由 Agent 单向校验客户端公钥。
- 支持 MCP 协议版本 `2026-07-28` 与 `2025-11-25`；HTTP 传输为 stateless，curl 即可调用。
- 不做外部 supervisor：Agent 被 SIGKILL 或进程主动脱离进程组后遗留的进程不处理。

设计与取舍细节见 [docs/DESIGN.md](docs/DESIGN.md)。
