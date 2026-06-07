# eBPF 零侵扰分布式调用链追踪系统

基于 eBPF 技术的零侵扰分布式调用链追踪服务，通过 Hook 内核态网络系统调用，无需修改应用代码即可实现全链路追踪。

## ✨ 核心特性

### 🎯 零侵扰追踪
- **eBPF 内核态 Hook**: 捕获 `connect/accept/sendto/recvfrom` 等系统调用
- **无需代码侵入**: 应用程序无需任何修改，即可实现全链路追踪
- **低性能损耗**: 内核态数据过滤，用户态仅处理必要数据

### 🔗 多协议支持
- **HTTP/1.1**: 自动解析请求方法、路径、状态码、Header
- **gRPC**: 识别服务名、方法名、状态码
- **Redis**: 解析命令、Key、参数

### 📊 动态采样
- **高延迟请求 100% 采样**: >500ms 的请求全部保留
- **低延迟请求 1% 采样**: 正常流量按比例采样
- **错误请求强制采样**: HTTP 4xx/5xx 全部保留
- **自适应采样**: 根据流量压力动态调整采样率

### 💾 高性能存储
- **ClickHouse 列式存储**: 支持 PB 级时序数据
- **数据压缩**: ZSTD 压缩算法，存储成本降低 80%
- **TTL 自动过期**: 数据自动清理

### 🌐 REST API
- `GET /api/v1/trace/{traceId}` - 查询完整调用链
- `GET /api/v1/traces` - 按条件搜索调用链
- `GET /api/v1/services` - 获取服务列表
- `GET /api/v1/services/{name}/stats` - 服务性能统计
- `GET /api/v1/service-map` - 服务拓扑图

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     应用服务器 (Linux)                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐            │
│  │  业务进程  │    │  业务进程  │    │  业务进程  │            │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘            │
└────────┼──────────────────┼──────────────────┼───────────────────┘
         │ 系统调用          │ 系统调用          │ 系统调用
┌────────▼──────────────────▼──────────────────▼───────────────────┐
│                      Linux 内核                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  eBPF 程序 (network_trace.bpf.c)                         │    │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐        │    │
│  │  │tcp_    │  │tcp_    │  │tcp_    │  │tcp_    │        │    │
│  │  │connect │  │accept  │  │sendmsg │  │cleanup │...     │    │
│  │  └────────┘  └────────┘  └────────┘  └────────┘        │    │
│  │                     BPF Maps                              │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │    │
│  │  │connections │  │socket_to_  │  │ perf_event │         │    │
│  │  │            │  │conn        │  │ _array      │         │    │
│  │  └────────────┘  └────────────┘  └────────────┘         │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ perf buffer
┌──────────────────────────────────▼───────────────────────────────┐
│                     用户态采集程序 (Go)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ eBPF 加载器 │  │ 协议解析器  │  │ 调用链关联  │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ 动态采样器  │  │ 批量写入器  │  │  REST API   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
└─────────┼─────────────────┼─────────────────┼────────────────────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            ▼
                    ┌──────────────┐
                    │  ClickHouse  │
                    │  时序数据库  │
                    └──────────────┘
```

## 📋 系统要求

### 内核要求
- Linux Kernel >= 5.10 (推荐 5.15+)
- 支持 BPF, BTF, KPROBES
- 内核配置: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_KPROBES=y`

### 权限要求
- `root` 或 `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`
- BPF 文件系统挂载: `mount -t bpf bpf /sys/fs/bpf`

## 🚀 快速开始

### 方式一: Docker Compose 部署 (推荐)

```bash
# 1. 克隆项目
git clone <repository-url>
cd ebpf-apm

# 2. 启动服务
docker-compose up -d

# 3. 查看服务状态
docker-compose ps

# 4. 测试 API
curl http://localhost:8080/api/v1/health
```

### 方式二: 源码编译运行

```bash
# 1. 安装依赖
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go

# 2. 生成 eBPF 绑定
make generate

# 3. 编译
make build

# 4. 初始化 ClickHouse  schema
sudo ./bin/ebpf-apm --config config.yaml --init-schema

# 5. 运行追踪服务
sudo ./bin/ebpf-apm --config config.yaml
```

## 📚 API 文档

### 查询调用链

```http
GET /api/v1/trace/{traceId}
```

**响应示例:**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "traceId": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "rootSpan": {
      "spanId": "1234567890abcdef",
      "parentSpanId": "",
      "serviceName": "gateway-service",
      "operation": "GET /api/users",
      "protocol": "http",
      "startTime": "2024-01-01T12:00:00Z",
      "durationMs": 250.5,
      "errorCode": 200,
      "payloadSize": 1024,
      "children": [
        {
          "spanId": "fedcba0987654321",
          "parentSpanId": "1234567890abcdef",
          "serviceName": "user-service",
          "operation": "GetUser",
          "protocol": "grpc",
          "durationMs": 120.3,
          "errorCode": 0,
          "children": [
            {
              "spanId": "1122334455667788",
              "parentSpanId": "fedcba0987654321",
              "serviceName": "redis",
              "operation": "GET user:123",
              "protocol": "redis",
              "durationMs": 5.2,
              "errorCode": 0
            }
          ]
        }
      ]
    },
    "durationMs": 250.5
  }
}
```

### 搜索调用链

```http
GET /api/v1/traces?service=user-service&minLatency=100&startTime=1704067200000&endTime=1704153600000
```

### 获取服务拓扑

```http
GET /api/v1/service-map?startTime=1704067200000&endTime=1704153600000
```

## 🔧 配置说明

```yaml
server:
  http_port: 8080

clickhouse:
  host: localhost
  port: 9000
  database: ebpf_apm

sampling:
  high_latency_threshold_ms: 500    # 高延迟阈值
  high_latency_sample_rate: 1.0    # 高延迟采样率 100%
  low_latency_sample_rate: 0.01    # 低延迟采样率 1%

protocols:
  http:
    enabled: true
    ports: [80, 8080, 3000]
  grpc:
    enabled: true
    ports: [50051, 9000]
  redis:
    enabled: true
    ports: [6379]
```

## 📊 数据模型

### spans 表

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | DateTime64(9) | 事件时间戳 |
| trace_id | FixedString(32) | 追踪ID |
| span_id | FixedString(16) | 跨度ID |
| parent_span_id | FixedString(16) | 父跨度ID |
| service_name | LowCardinality(String) | 服务名 |
| operation | String | 操作名 |
| protocol | LowCardinality(String) | 协议 (http/grpc/redis) |
| duration_ms | Float64 | 耗时 (毫秒) |
| error_code | Int32 | 错误码/状态码 |
| payload_size | UInt32 | Payload 大小 |
| source_ip / dest_ip | IPv4 | 源/目的IP |
| source_port / dest_port | UInt16 | 源/目的端口 |
| pid | UInt32 | 进程ID |
| comm | String | 进程名 |
| path | String | 请求路径 |

## 🎯 使用场景

1. **微服务调用链追踪**: 自动发现服务间调用关系
2. **性能瓶颈分析**: 快速定位慢查询、高延迟接口
3. **故障排查**: 追踪错误请求的完整链路
4. **架构可视化**: 实时生成服务拓扑图
5. **容量规划**: 基于真实流量数据进行容量评估

## 🔍 监控指标

- `ebpf_apm_events_total`: 总事件数
- `ebpf_apm_events_sampled`: 采样事件数
- `ebpf_apm_high_latency_count`: 高延迟请求数
- `ebpf_apm_spans_stored`: 已存储 span 数

```bash
curl http://localhost:8080/metrics
```

## 🛠️ 故障排查

### 常见问题

**1. 无法加载 eBPF 程序**
```bash
# 检查内核版本
uname -r

# 检查 BPF 支持
zcat /proc/config.gz | grep BPF

# 挂载 BPF 文件系统
sudo mount -t bpf bpf /sys/fs/bpf
```

**2. 权限不足**
```bash
# 需要 root 权限运行
sudo ./bin/ebpf-apm

# 或使用 capabilities
sudo setcap cap_sys_admin,cap_net_admin,cap_sys_ptrace,cap_bpf+ep ./bin/ebpf-apm
```

**3. ClickHouse 连接失败**
```bash
# 检查连接
clickhouse-client --host localhost --port 9000

# 查看日志
docker logs ebpf-apm-clickhouse
```

## 📄 License

GPL-2.0 (由于 eBPF 代码使用 GPL 许可证)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request!

---

**注意**: 本项目需要在 Linux 环境下运行，且需要 root 权限。Windows 和 macOS 仅支持代码开发，不支持 eBPF 追踪功能。
