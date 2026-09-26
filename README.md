# CIDR Policy Normalizer

基于 **Python + FastAPI + 标准库 `ipaddress`** 的 CIDR 策略规范化 API。

接收 `allow` 与 `deny` 两个 CIDR 列表，分别对 **IPv4 / IPv6** 计算集合差
**allow − deny**，返回与原策略**等价、互不重叠且数量最少**的 CIDR 集合。
另提供地址判定（`/evaluate`）、策略对比（`/compare`）、规则影响审计
（`/audit-rules`）、策略最小化（`/minimize-policy`）、子网分配
（`/allocate`）与地址清单**前缀保持脱敏**（`/anonymize`）接口。

- deny 前缀切穿 allow 网段时，按二叉前缀树**递归对半拆分**直到边界对齐；
- 仅当两个网段构成**完整相邻的兄弟前缀**（同一父网的左右两半）时才合并，
  借助 `ipaddress.collapse_addresses` 实现，保证最小化且不会跨边界聚合；
- 输出按 **地址族（IPv4 → IPv6）→ 网络地址 → 前缀长度** 稳定排序；
- 统计 allow / deny 的输入数量、去重后数量（按族拆分）与最终输出数量；
- `/audit-rules` 在单个 scope 内基于 **CIDR 分区**（不枚举地址）逐条判断
  规则为 `effective` / `shadowed` / `out_of_scope`，给出最小 witness IP 与
  使其无法获胜的规则索引集合，兼容 IPv4/IPv6；
- `/minimize-policy` 在单个 scope 内基于 **CIDR 分区 + 精确分支限界搜索**
  （不枚举地址、不逐条贪心删除）求出与原策略判定完全一致的**最少规则子集**，
  多组最少解按保留规则的 `(side, index)` 序列字典序取唯一结果；
- `/allocate` 在单个 scope 内为多条申请分配互不重叠、避开占用网段的子网，
  按申请顺序取**网络地址序列字典序最小**的完整可行方案（必要时回溯）；
- `/anonymize` 用 64 位十六进制（32 字节）HMAC 密钥对裸 IPv4/IPv6 地址与
  严格 CIDR 做**前缀保持脱敏**：同一密钥下映射稳定且一一对应，任意两地址的
  **最长公共前缀长度不变**，CIDR 脱敏后按原前缀长度清零主机位返回规范网段；
- 非法 CIDR（格式错误、越界前缀、主机位非零）统一返回 **HTTP 422**。

## 一条命令启动

依赖在镜像构建时安装完成，容器启动即提供服务：

```bash
docker compose up -d --build
```

服务监听宿主机 **8000** 端口（容器内固定 8000），访问地址：
**http://localhost:8000**

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

交互式文档：<http://localhost:8000/docs>

## 配置

无需任何必填配置。唯一可选项是宿主机映射端口（容器内始终为 8000）：

```bash
HOST_PORT=9000 docker compose up -d --build   # 宿主机改用 9000
```

默认端口：**8000**（见 `docker-compose.yml` 的 `${HOST_PORT:-8000}:8000`）。

## API

### `POST /normalize`

请求体：

| 字段   | 类型       | 说明                                   |
| ------ | ---------- | -------------------------------------- |
| `allow` | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`  | `string[]` | 拒绝列表，规则同上                     |

CIDR 规则：

- 标准 CIDR：`10.0.0.0/24`、`2001:db8::/32`；
- 裸地址按主机前缀处理：`10.0.0.1` ≡ `10.0.0.1/32`，`::1` ≡ `::1/128`；
- 主机位非零（如 `10.0.0.1/24`）视为非法，返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
        "deny":  ["10.0.0.128/25", "2001:db8:1::/48"]
      }'
```

响应：

```json
{
  "ipv4": ["10.0.0.0/25"],
  "ipv6": ["2001:db8::/48", "2001:db8:2::/47", "... 共 16 段 ..."],
  "stats": {
    "allow": {"input": 3, "unique": 2, "duplicates_removed": 1, "ipv4": 1, "ipv6": 1},
    "deny":  {"input": 2, "unique": 2, "duplicates_removed": 0, "ipv4": 1, "ipv6": 1},
    "output": {"ipv4": 1, "ipv6": 16, "total": 17}
  }
}
```

字段说明：

- `ipv4` / `ipv6`：allow − deny 的最小 CIDR 列表，按网络地址、前缀长度排序；
- `stats.allow` / `stats.deny`：
  - `input`：请求中的原始条目数；
  - `unique`：去重后的网络数；
  - `duplicates_removed`：被去掉的重复条目数；
  - `ipv4` / `ipv6`：去重后各地址族的网络数；
- `stats.output`：最终输出的 IPv4 / IPv6 及总网段数。

非法输入返回 422：

```bash
curl -i -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{"allow": ["10.0.0.1/24"], "deny": []}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body","allow"],
#   "msg":"Value error, 10.0.0.1/24 has host bits set", ...}]}
```

### `POST /evaluate`

接收与 `/normalize` 相同的 `allow` / `deny` CIDR 列表，外加一个 `addresses`
裸地址列表，对每个地址做**最长前缀匹配**，并按 `addresses` 的原顺序逐条返回
判定结果。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `allow`     | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`      | `string[]` | 拒绝列表，规则同上                     |
| `addresses` | `string[]` | 待判定的**裸 IP 地址**（不接受 CIDR 记法），顺序即返回顺序 |

匹配优先级（逐级决胜）：

1. **前缀长度最长者胜**；
2. 前缀长度相同 → **deny 胜过 allow**；
3. 仍相同（同一列表内的重复项）→ 按该列表中的**原顺序**取第一条；
4. 没有任何条目包含该地址 → `unmatched`。

示例：

```bash
curl -s -X POST http://localhost:8000/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/25", "2001:db8::/32"],
        "deny":  ["10.0.0.0/25"],
        "addresses": ["10.0.0.1", "10.0.0.200", "192.0.2.1", "2001:db8::1"]
      }'
```

响应（与 `addresses` 等长、同序）：

```json
[
  {"decision": "deny",      "matched_cidr": "10.0.0.0/25", "matched_side": "deny"},
  {"decision": "allow",     "matched_cidr": "10.0.0.0/24", "matched_side": "allow"},
  {"decision": "unmatched", "matched_cidr": null,           "matched_side": null},
  {"decision": "allow",     "matched_cidr": "2001:db8::/32", "matched_side": "allow"}
]
```

字段说明：

- `decision`：`allow` / `deny` / `unmatched`；
- `matched_cidr`：获胜条目的规范 CIDR（裸地址条目规范化为主机前缀
  `10.0.0.1/32`），未匹配时为 `null`；
- `matched_side`：获胜条目来自 `allow` 还是 `deny`，未匹配时为 `null`。

非法 CIDR 或非法地址（包括给 `addresses` 传入 `10.0.0.1/24` 这样的 CIDR
记法）统一返回 **HTTP 422**。

### `POST /compare`

在**单个 `scope` CIDR** 范围内，比较 **baseline（基线）** 与
**candidate（候选）** 两组 allow/deny 策略的判定差异。两组策略各自沿用
`/evaluate` 的**最长前缀、同长度 deny 优先**规则。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `scope`     | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定比较区域；主机位非零返回 422 |
| `baseline`  | `object`   | 基线策略，形如 `{"allow": [...], "deny": [...]}`，省略视为两个空列表 |
| `candidate` | `object`   | 候选策略，结构同 `baseline`            |

处理过程：

1. 分别把 scope 对 baseline、candidate **递归切分为判定恒定的互不重叠
   CIDR**（只有更具体的条目边界才触发对半拆分）；
2. **叠加（求交）两侧分区**，只保留两侧判定不同的区域；
3. 对差异区域中**相邻且转换类型相同的完整兄弟网段递归合并**（转换不同的
   兄弟、不等长的相邻网段不合并）。

示例：

```bash
curl -s -X POST http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "baseline":  {"allow": ["10.0.0.0/24"], "deny": []},
        "candidate": {"allow": ["10.0.0.0/25"], "deny": ["10.0.0.128/26"]}
      }'
```

响应（按 IPv4→IPv6、网络地址、前缀长度稳定排序）：

```json
{
  "differences": [
    {"cidr": "10.0.0.128/26", "baseline_decision": "allow", "candidate_decision": "deny"},
    {"cidr": "10.0.0.192/26", "baseline_decision": "allow", "candidate_decision": "unmatched"}
  ],
  "transition_counts": {
    "allow->deny": "64",
    "allow->unmatched": "64",
    "deny->allow": "0",
    "deny->unmatched": "0",
    "unmatched->allow": "0",
    "unmatched->deny": "0"
  }
}
```

字段说明：

- `differences[].cidr`：判定发生变化的互不重叠区域；
- `differences[].baseline_decision` / `candidate_decision`：该区域内
  恒定的两侧判定，取值 `allow` / `deny` / `unmatched`，二者必不相同；
- `transition_counts`：六种转换类型 `"baseline->candidate"` 各自覆盖的
  **地址数（十进制字符串）**，未出现的转换为 `"0"`；计数与
  `differences` 覆盖的地址一一对应（例如两个 `/26` 各 64 个地址）。

说明：

- 与 scope 不同地址族的条目自动忽略；等于或包含 scope 的条目在整个
  scope 上生效（例如 scope 为 `10.0.0.0/25` 时，两侧相同的
  `10.0.0.0/24` 不产生差异）；
- 两组策略完全一致（或 scope 内判定一致）时 `differences` 为空数组；
- `scope` 缺失、非法、主机位非零，或嵌套的 baseline/candidate 中存在
  非法 CIDR，统一返回 **HTTP 422**。

### `POST /audit-rules`

在**单个 `scope` CIDR** 内，接收现有 allow/deny 两个列表，**按输入侧与原序**
逐条审计每条规则是否真正影响最终判定。判定规则沿用 `/evaluate`：

1. **前缀长度最长者胜**；
2. 前缀长度相同 → **deny 胜过 allow**；
3. 仍相同（同一列表内的重复项）→ 按该列表中的**原顺序**取第一条（重复规则
   的稳定优先级）。

分析完全基于 **CIDR 分区**（自 scope 起递归对半切分，只按网段集合运算），
**不枚举任何地址**，因此兼容巨大 IPv6 网段（如 `::/0`），也兼容 IPv4。

请求体：

| 字段    | 类型       | 说明                                   |
| ------- | ---------- | -------------------------------------- |
| `scope` | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定审计区域；主机位非零返回 422 |
| `allow` | `string[]` | 允许列表，可省略（默认 `[]`）；每条必须与 scope **同地址族** |
| `deny`  | `string[]` | 拒绝列表，规则同 `allow`               |

每条规则的审计结论（`status`）：

- **`effective`**：规则在 scope 内**至少赢下一个区域**（对该区域内地址起决定
  作用）。响应给出 `witness`：该规则获胜区域内**数值最小的网络地址**（裸 IP
  字符串，IPv6 采用压缩写法）；它一定落在获胜区域内，且位于某个分区网段的
  边界上，无需枚举地址即可算出。
- **`shadowed`**：规则与 scope 相交，但在 scope 内**处处无法获胜**。响应给出
  `shadowed_by`：**真正赢下其区域各部分的规则的 `(side, index)` 集合**（去重、
  按 side、index 排序）；只有自己也能获胜的规则才会出现——本身也被遮蔽的死
  规则不会被列入。`index` 为该规则在对应输入列表中的 **0 基下标**。
- **`out_of_scope`**：规则 CIDR 与 scope **完全不相交**（同地址族但无交集），
  对 scope 内判定没有任何影响。大于等于 scope 的规则按 scope 裁剪后的区域
  分析；裸地址按 `/32`、`/128` 处理。

> 注意：与 `/compare` 静默忽略异地址族条目的策略不同，`/audit-rules` 中任何
> 规则与 scope **地址族不一致都直接返回 422**。

示例：

```bash
curl -s -X POST http://localhost:8000/audit-rules \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "allow": [
          "10.0.0.0/24",
          "10.0.0.0/25",
          "10.0.0.0/25"
        ],
        "deny": [
          "10.0.0.0/25",
          "10.1.0.0/16"
        ]
      }'
```

响应（`allow` / `deny` 各自与输入**等长、同序**）：

```json
{
  "allow": [
    {"side": "allow", "index": 0, "cidr": "10.0.0.0/24",
     "status": "effective", "witness": "10.0.0.128", "shadowed_by": null},
    {"side": "allow", "index": 1, "cidr": "10.0.0.0/25",
     "status": "shadowed", "witness": null,
     "shadowed_by": [{"side": "deny", "index": 0}]},
    {"side": "allow", "index": 2, "cidr": "10.0.0.0/25",
     "status": "shadowed", "witness": null,
     "shadowed_by": [{"side": "deny", "index": 0}]}
  ],
  "deny": [
    {"side": "deny", "index": 0, "cidr": "10.0.0.0/25",
     "status": "effective", "witness": "10.0.0.0", "shadowed_by": null},
    {"side": "deny", "index": 1, "cidr": "10.1.0.0/16",
     "status": "out_of_scope", "witness": null, "shadowed_by": null}
  ]
}
```

字段说明：

- `side` / `index` / `cidr`：规则来源侧（`allow` / `deny`）、在该侧输入列表中
  的 0 基下标、规范 CIDR；
- `status`：`effective` / `shadowed` / `out_of_scope`；
- `witness`：仅 `effective` 时出现，为该规则获胜区域内数值最小的 IP（上例中
  allow `/24` 只在高地址半区 `10.0.0.128/25` 获胜，故 witness 为
  `10.0.0.128` 而非规则自身起点 `10.0.0.0`）；
- `shadowed_by`：仅 `shadowed` 时出现，为赢下该规则区域各部分的规则引用集合；
  上例中两条重复的 allow `/25`（index 1、2）都在同长度对决中败给
  deny index 0，故二者 `shadowed_by` 相同。

`scope` 缺失/非法/主机位非零、规则 CIDR 非法，或规则与 scope 地址族不一致，
统一返回 **HTTP 422**。

### `POST /minimize-policy`

在**单个 `scope` CIDR** 内，接收合计**不超过 16 条**的 allow/deny 规则，求出
一个规则子集，使其对 scope 内**每个地址的判定都与原策略完全一致**，且子集的
规则数**最少**。判定规则沿用 `/evaluate`（最长前缀 → 同长度 deny 优先 →
同列表原序优先）。

算法基于 **CIDR 分区**（自 scope 起递归对半切分，只做网段运算）配合
**精确的分支限界子集搜索**：先按原策略把 scope 切成获胜者恒定的最大 CIDR 瓦片，
再以“最受限瓦片优先 + 强制纳入/排除规则”的深度优先搜索枚举可行子集——
**既不枚举任何 IP 地址，也不采用逐条贪心删除**（逐条贪心无法保证全局最少），
因此可处理 `::/0` 这类巨大 IPv6 scope。多组同样最少的解，按保留规则的
`(side, index)` 序列取**字典序最小**的唯一结果（`allow` 排在 `deny` 前，
两侧各自按原下标升序）。

请求体：

| 字段    | 类型       | 说明                                   |
| ------- | ---------- | -------------------------------------- |
| `scope` | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），限定最小化区域；主机位非零返回 422 |
| `allow` | `string[]` | 允许列表，可省略（默认 `[]`）；每条必须与 scope **同地址族** |
| `deny`  | `string[]` | 拒绝列表，规则同 `allow`               |

> `allow` 与 `deny` 的**总条数不得超过 16**，否则返回 422；任一规则与 scope
> 地址族不一致同样返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/minimize-policy \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "allow": ["10.0.0.0/24", "10.0.0.0/25"],
        "deny":  ["10.0.0.128/25"]
      }'
```

原策略：低地址半区 `10.0.0.0/25` 由 allow 获胜（allow `/25` 与 `/24` 同覆盖时
取更长的 `/25`，但二者判定相同），高地址半区 `10.0.0.128/25` 由 deny 获胜。
allow index 1（`/25`）是多余的——保留更宽的 allow index 0（`/24`）即可覆盖低
半区且在高半区输给 deny。响应：

```json
{
  "retained": [
    {"side": "allow", "index": 0, "cidr": "10.0.0.0/24", "witness": "10.0.0.0"},
    {"side": "deny", "index": 0, "cidr": "10.0.0.128/25", "witness": "10.0.0.128"}
  ],
  "removed": [
    {"side": "allow", "index": 1, "cidr": "10.0.0.0/25"}
  ]
}
```

字段说明：

- `retained` / `removed`：**保留 / 删除的规则引用**，均按**原输入顺序**返回——
  先按 index 列出全部 allow 引用，再按 index 列出全部 deny 引用；两组合起来恰好
  是全部输入规则且互不重叠；
- 每条引用含 `side`（`allow` / `deny`）、`index`（该侧输入列表中的 0 基下标）、
  `cidr`（规范 CIDR）；
- `retained[]` 额外含 `witness`：该规则在**最小方案**中获胜区域内**数值最小的
  IP 地址**（它由最小方案自身的获胜者分区算出，可能落在分区边界上，无需枚举地址；
  IPv6 采用压缩写法）。`removed[]` 不含 `witness`。

其他要点：

- 与 scope 完全不相交的规则不影响任何判定，一律进入 `removed`；
- 同长度被 deny 压制的 allow、同侧被更早重复项遮蔽的规则等“从不获胜”的规则都会
  被删除；
- 若存在多组等大的最少解（例如宽 `/24` 与窄 `/25` 两条 allow 都能配合同一条
  deny 构成二规则解），按保留规则的 `(side, index)` 序列字典序取唯一结果，
  上例即保留 `("allow", 0)` 而非 `("allow", 1)`；
- 空策略（无规则）返回 `{"retained": [], "removed": []}`；
- 规则总数超过 16、`scope` 缺失/非法/主机位非零、规则 CIDR 非法，或规则与 scope
  地址族不一致，统一返回 **HTTP 422**。

### `POST /allocate`

在**单个 `scope` CIDR** 内，为多条子网申请分配**互不重叠、且不触碰占用
网段**的子网。按申请顺序把各分配结果的网络地址组成序列，返回**字典序最小
的完整可行方案**——靠前的申请优先占据低地址，必要时自动回溯；任一申请
无法满足时返回 **HTTP 409**，且不返回任何部分分配。

请求体：

| 字段                     | 类型       | 说明                                   |
| ------------------------ | ---------- | -------------------------------------- |
| `scope`                  | `string`   | **必填**，单个 CIDR（IPv4 或 IPv6），分配范围；主机位非零返回 422 |
| `occupied`               | `string[]` | 已占用 CIDR 列表，可省略（默认 `[]`）。每条必须与 scope **同地址族**、**位于 scope 内**且**互不重叠**，否则 422 |
| `requests`               | `object[]` | 申请列表，按此顺序分配，可省略（默认 `[]`） |
| `requests[].id`          | `string`   | 申请标识，非空且**不可重复**（重复返回 422） |
| `requests[].prefix_length` | `int`    | 申请的前缀长度；IPv4 为 0–32、IPv6 为 0–128，越界返回 422 |

说明：

- `prefix_length` **小于 scope 前缀长度**（如 /24 scope 里申请 /16）不属于
  非法输入，而是**永远无法满足的申请**，按 409 处理；
- 分配结果彼此不重叠、不碰 `occupied`，且都是 scope 的子网；
- 响应中的 `allocations` **保持申请顺序**（不是地址顺序）。

示例（需要回溯的情形：若把 `small` 贪心地放进低地址的 /25，`big` 的 /24
将无处安放；搜索回溯后把 `small` 挪到 `10.0.1.128/25`）：

```bash
curl -s -X POST http://localhost:8000/allocate \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/23",
        "occupied": ["10.0.1.0/25"],
        "requests": [
          {"id": "small", "prefix_length": 25},
          {"id": "big",   "prefix_length": 24}
        ]
      }'
```

响应：

```json
{
  "allocations": [
    {"id": "small", "cidr": "10.0.1.128/25"},
    {"id": "big",   "cidr": "10.0.0.0/24"}
  ],
  "remaining": [],
  "remaining_addresses": "0"
}
```

字段说明：

- `allocations`：与 `requests` 等长、同序的分配结果，`cidr` 为规范 CIDR；
- `remaining`：分配后 scope 内剩余空间的**最小 CIDR 集合**（互不重叠、
  按网络地址排序）；
- `remaining_addresses`：剩余地址总数，**十进制字符串**（IPv6 下会超出
  JSON 安全整数范围，与 `/compare` 的计数口径一致）。

无法满足时返回 409，响应体不含任何分配结果：

```bash
curl -i -X POST http://localhost:8000/allocate \
  -H 'Content-Type: application/json' \
  -d '{
        "scope": "10.0.0.0/24",
        "occupied": ["10.0.0.0/25"],
        "requests": [
          {"id": "x", "prefix_length": 25},
          {"id": "y", "prefix_length": 25}
        ]
      }'
# HTTP/1.1 409 Conflict
# {"detail":"no complete allocation satisfies all requests within scope
#   '10.0.0.0/24'; no partial allocation returned"}
```

重复 id、越界前缀长度、非法网段（格式错误、主机位非零、与 scope 不同族、
超出 scope、占用列表互相重叠）统一返回 **HTTP 422**。

### `POST /anonymize`

共享地址清单时，对**裸 IPv4/IPv6 地址**与**严格 CIDR** 做基于 HMAC-SHA256
的**前缀保持（prefix-preserving）脱敏**。映射由请求中的 64 位十六进制
（32 字节 / 256 位）密钥决定：

- **稳定**：同一密钥下，同一地址永远得到同一结果；
- **一一对应**：两个不同地址（同族）不可能脱敏成同一地址，原始位可从高位
  到低位逐位还原；
- **前缀保持**：任意两地址脱敏前后的**最长公共前缀长度完全一致**——相同的
  原始位用同一填充位异或后仍相同，第一个不同位遇到的填充位对双方相同，
  异或后仍不同；
- CIDR 脱敏后**前缀长度不变**、主机位重新清零，返回规范网段，故网段包含
  关系与同族 CIDR 列表的结构在脱敏后保持不变。

请求体：

| 字段        | 类型       | 说明                                   |
| ----------- | ---------- | -------------------------------------- |
| `key_hex`   | `string`   | **必填**，恰好 64 个十六进制字符（32 字节密钥），大小写均可，允许首尾空白 |
| `addresses` | `string[]` | 待脱敏的**裸 IP 地址**（不接受 CIDR 记法），可省略（默认 `[]`）；返回顺序与此一致 |
| `cidrs`     | `string[]` | 待脱敏的**严格 CIDR**（主机位必须为零；裸地址按 `/32`、`/128` 处理），可省略（默认 `[]`）；返回顺序与此一致 |

逐位算法（按**网络位序**，自最高位起）：对第 `i` 位（0 基），以密钥对以下拼接
字节串计算 HMAC-SHA256，取摘要**首字节的最高位**与当前原始位异或，得到脱敏位：

1. **地址族字节**：IPv4 为 `0x04`、IPv6 为 `0x06`（即 IP 版本号）；
2. **当前位序字节**：`i`（IPv4 取 0–31，IPv6 取 0–127）；
3. **此前原始位补零串**：第 `i` 位之前的原始位右对齐回填到 4（IPv4）或
   16（IPv6）字节，当前位及其后各位一律补零。

填充位只依赖此前的原始位，这正是映射可逆且前缀保持的原因。

示例：

```bash
curl -s -X POST http://localhost:8000/anonymize \
  -H 'Content-Type: application/json' \
  -d '{
        "key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "addresses": ["192.168.0.1", "192.168.0.2", "2001:db8::1"],
        "cidrs": ["10.0.0.0/8", "192.168.0.0/24", "2001:db8::/32"]
      }'
```

响应（两个列表各自与输入**等长、同序**）：

```json
{
  "addresses": [
    "236.222.104.188",
    "236.222.104.191",
    "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a"
  ],
  "cidrs": [
    "77.0.0.0/8",
    "236.222.104.0/24",
    "d5af:46c8::/32"
  ]
}
```

上例中 `192.168.0.1` 与 `192.168.0.2` 原有 30 位公共前缀（`.1=...000001`、
`.2=...000010`），其脱敏结果 `236.222.104.188` 与 `236.222.104.191` 同样共享
`/30`；`/8`、`/24`、`/32` 网段脱敏后仍是同长度的规范网段。

非法输入统一返回 **HTTP 422**：

- `key_hex` 缺失、不是字符串、长度不为 64 或含非十六进制字符；
- `addresses` 中出现非法地址或 `10.0.0.1/32` 这样的 CIDR 记法；
- `cidrs` 中出现非法网段或主机位非零（如 `10.0.0.1/24`）。

## 算法说明

1. **解析校验**：`ipaddress.ip_network(value, strict=True)` 严格解析；
2. **族拆分 + 输入折叠**：IPv4、IPv6 独立处理，先对 allow / deny 各自
   `collapse_addresses` 去重、去重叠、去包含；
3. **递归差集**（`app/policy.py::_diff`）：对每个 allow 网络：
   - deny 等于或包含该网络 → 整个删除；
   - deny 与其不相交 → 整段保留；
   - deny 是其严格子网（切穿）→ 拆成左右两个兄弟半区递归处理，
     被整段拒绝的半区丢弃，未触及的半区整体保留；
4. **兄弟合并**：结果再次 `collapse_addresses`，只有完整相邻兄弟前缀
   才能合并回父前缀，从而保证等价性、互不重叠与最少数量；
5. **稳定排序**：按地址族、`network_address.packed`、前缀长度排序。

`/compare` 在同一套判定规则之上另走一条路径（`app/policy.py` 中
`_winner_partition` / `_overlay_partitions` / `_merge_labelled`）：

1. 对每组策略，自 scope 起按前缀树递归：scope 上的获胜条目（最长前缀、
   同长度 deny 优先）作为继承判定，严格子网把当前节点对半切开，判定
   恒定的半区整体保留；
2. 两侧分区叠加求交（任意两个相交的对齐前缀，交集必为较细者），只保留
   `baseline_decision != candidate_decision` 的瓦片；
3. 按转换标签做**带标签的完整兄弟合并**（不动点循环）：同一父网的左右
   两半都在、且转换类型完全相同时才合并，合并后的父网段继续向上合并。

`/audit-rules` 复用同一套**获胜者分区**（`app/policy.py` 中
`audit_rules` / `_winner_partition`）：分区把 scope 切成互不重叠、联合穷尽
scope 的最大 CIDR 瓦片，每块直接携带**获胜条目本体**（无获胜者则为
`unmatched`）。对每条规则：

1. CIDR 与 scope 不相交 → `out_of_scope`（对齐前缀只可能包含或不相交，
   不存在“切穿”）；
2. 否则取与该规则相交的瓦片集合（同样只有相等或包含关系）：
   - 其中存在获胜条目就是本规则的瓦片 → `effective`，witness 取这些瓦片中
     网络地址最小者（瓦片边界地址必在获胜区域内），全程只有网段运算，
     **不枚举地址**；
   - 否则 → `shadowed`，把各瓦片实际获胜条目的 `(side, index)` 去重收集为
     `shadowed_by`；无任何条目获胜的瓦片（`unmatched`）不贡献遮蔽者。

`/minimize-policy` 在获胜者分区之上做**精确最少子集搜索**（`app/policy.py` 中
`minimize_policy` / `_minimize_family`）：

1. 原策略经 `_winner_partition` 把 scope 切成携带获胜条目的最大 CIDR 瓦片。
   获胜者为 `None`（unmatched）的瓦片没有要求：任何覆盖它的规则都会赢得它，
   因此可行解里本来就不会保留覆盖它的规则；
2. 对每个带 side 标签的瓦片，把覆盖它、且与获胜侧同侧的规则作为候选
   （candidate），把覆盖它且匹配键严格更高的**异侧**规则记为该候选的阻挡集合
   （blockers）。同侧规则只会把获胜者换成另一条同判定规则，永远不构成阻挡；
3. 迭代式深度优先分支限界：每轮挑选**未被保证、候选数最少的瓦片**，要么保留其
   一个可行候选（同时强制排除该候选的全部 blockers），要么在已有候选被保留时走
   “只排除、不新增规则”的分支；某候选的 blocker 已被保留即判该候选失效，所有
   候选失效则剪枝回溯。初始上界是“原策略各瓦片获胜者去重后”的可行集合；
4. 状态用 `(retained, excluded)` 位掩码记忆化；规则按 `(side, index)` 规范序编号，
   搜索优先展开编号最小的候选，使规模相当下字典序最小的解尽早成为当前最优，最终
   唯一结果即所有最少解中 `(side, index)` 序列字典序最小者。全程只在 CIDR 瓦片
   与位掩码上运算，**不枚举 IP，也不逐条贪心删除规则**；
5. 确定保留集合后，对**最小方案本身**再做一次获胜者分区：每条保留规则至少赢下
   一个瓦片，其 `witness` 取它所赢瓦片中网络地址最小者。

`/allocate` 的搜索同样建立在 `scope − occupied` 的最小空闲集合之上
（`app/policy.py` 中 `_search` / `_fits` / `_subtract_free`）：

1. 空闲空间表示为排序、互不重叠的最小 CIDR 列表；每次分配用
   `address_exclude` 从包含它的空闲块中扣除，列表性质保持不变；
2. 按申请顺序做**深度优先搜索**：每条申请的候选子网按网络地址**升序**
   枚举，找到的第一个完整方案即为网络地址序列字典序最小者；任一申请
   无候选可放时回溯到上一申请的下一块候选；
3. 每个搜索节点先做**分粒度容量检查**（对每个申请前缀长度 p，比较
   尚未放置的申请折算成 /p 块的需求数与空闲空间可容纳的 /p 块数），
   不可行立即剪枝；失败的 `(深度, 空闲集合)` 状态记入备忘录避免重复
   搜索。

`/anonymize` 是逐位的 Crypto-PAn 式密钥变换（`app/anonymize.py`）：

1. 自最高位（IPv4 第 0 位、IPv6 第 0 位）起处理，第 `i` 位的 HMAC 消息为
   `地址族字节(4/6) ‖ 位序字节 i ‖ 前 i 个原始位右侧补零到 4/16 字节`，
   取 HMAC-SHA256 摘要首字节的最高位作为该位的填充位，与原始位异或；
2. 填充位只依赖**此前的原始位**：相同前缀的地址在分岔前逐位相同，分岔位
   对双方使用同一填充位，异或后必然仍不同——因此最长公共前缀长度不变；
3. 逆变换从高位向低位进行（恢复每位时其填充位只依赖已恢复的前缀），故同族
   映射是双射；同一次请求内对 `(族, 位序, 原始前缀)` 的填充位做缓存，地址
   共享前缀时不重复计算 HMAC；
4. CIDR 先对网络地址逐位脱敏，再以原前缀长度（`strict=False` 构造等价于按
   掩码清零主机位）规范化，得到的正是整个原始前缀在双射下的像网段。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行测试（仅核心测试依赖标准库；API 测试需安装 fastapi、httpx、pytest）：

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```

测试包含与 `ipaddress.address_exclude` 参考实现对拍的 IPv4/IPv6 随机性质
用例，验证结果的等价性与最小性；`/anonymize` 的测试覆盖已知向量、同族双射、
逐位逆变换、最长公共前缀保持与 CIDR 像网段包含关系。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用：GET /health、POST /normalize、/evaluate、/compare、/audit-rules、/minimize-policy、/allocate、/anonymize
│   ├── policy.py      # 解析、递归拆分、兄弟合并、统计、最长前缀匹配、获胜者分区、规则审计、分区对比、最少规则子集搜索、子网分配搜索（仅 ipaddress）
│   ├── anonymize.py   # 前缀保持的 HMAC-SHA256 逐位脱敏（裸地址与严格 CIDR，仅标准库）
│   └── schemas.py     # Pydantic 请求/响应模型与 422 校验
├── tests/
│   ├── test_policy.py    # 核心算法单测 + 随机对拍（含 /compare、/audit-rules 逐地址对拍、/minimize-policy 子集暴力枚举对拍、/allocate 暴力枚举对拍）
│   ├── test_anonymize.py # 脱敏核心单测：已知向量、稳定性、一一对应、可逆性、最长公共前缀保持、CIDR 像网段对拍
│   └── test_api.py       # API 层测试（422、409、统计、空请求等）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
