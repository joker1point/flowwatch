# flowwatch-alert（Catrace 插件）

把 flowwatch 的**代理流量哨兵**（`flowwatch/scripts/proxy_sentinel.py`）告警，弹成 Catrace 桌面小窗卡片。

## 安装

1. Catrace → 插件页 → 「打开插件目录」
2. 把本目录（`flowwatch-alert`）整个拷进插件目录
3. 在插件页里启用（启用 = 信任其代码；本插件的 sidecar 只是一个监听回环地址的本地 HTTP 服务）

需要本机有 Node.js（sidecar 用）。

## 工作方式

sidecar 监听 `127.0.0.1:23457`（被占用时自动 +1，最多试 3 个端口）：

- `POST /alert` → 弹卡片
  ```json
  { "title": "⚠️ 代理流量异常", "body": "近 60 分钟代理上行 12.3 GB", "level": "warning", "sticky": true }
  ```
- `GET /health` → 运行状态（端口、已发布条数等）

flowwatch 侧 `proxy_sentinel.py` 会自动探测 `23457/23458/23459` 并推送；推不到时退回原来的置顶弹窗（不会丢告警）。

## 手动测试

```bash
curl -X POST http://127.0.0.1:23457/alert -H "Content-Type: application/json" -d "{\"title\":\"测试\",\"body\":\"hello\"}"
```

或在插件设置页点「发送测试告警」。
