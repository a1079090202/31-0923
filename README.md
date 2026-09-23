# 请求签名 API

基于 FastAPI 的单文件请求签名服务：对查询参数做规范化排序与 RFC 3986 百分号编码，构造四行待签串，使用 HMAC-SHA256 计算签名（十六进制小写）。

## 启动

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

**端口：8000**（启动后交互式文档见 http://localhost:8000/docs）

## 接口

### POST /sign

请求体（JSON）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `method` | string | HTTP 方法，按原样进入待签串 |
| `path` | string | 请求路径，按原样进入待签串 |
| `params` | array | 查询参数键值对数组，允许重复键；每项为 `{"key": "...", "value": "..."}`，`value` 可省略（视为空值） |
| `secret` | string | 签名密钥（HMAC-SHA256 的 key，按 UTF-8 编码） |
| `timestamp` | string | 十位十进制时间戳，如 `"1700000000"` |

请求示例：

```json
{
  "method": "GET",
  "path": "/v1/resource",
  "params": [
    {"key": "b", "value": "2"},
    {"key": "a", "value": "1"},
    {"key": "a", "value": ""},
    {"key": "sp", "value": "a b"}
  ],
  "secret": "s3cr3t",
  "timestamp": "1700000000"
}
```

响应（200）：

```json
{
  "canonical_query": "a&a=1&b=2&sp=a%20b",
  "signature": "<64 位十六进制小写>"
}
```

curl 示例：

```bash
curl -s -X POST http://localhost:8000/sign \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/v1/resource","params":[{"key":"b","value":"2"},{"key":"a","value":"1"},{"key":"a","value":""},{"key":"sp","value":"a b"}],"secret":"s3cr3t","timestamp":"1700000000"}'
```

## 签名规则

1. **排序**：查询参数按键的 UTF-8 字节序升序排列；键相同时，按值的 UTF-8 字节序升序排列。
2. **编码**：键与值分别做 RFC 3986 百分号编码——保留 `A-Z a-z 0-9` 与 `-_.~`，其余字节编码为 `%XX`（空格为 `%20`，不是 `+`）；非 ASCII 字符按 UTF-8 编码。
3. **拼接**：以 `k=v` 形式用 `&` 连接；**空值只保留键**（如 `a`，不带 `=`）。
4. **待签串**：方法、请求路径、规范化查询串、时间戳四行，以换行符 `\n` 连接（末尾无换行）：

   ```
   GET
   /v1/resource
   a&a=1&b=2&sp=a%20b
   1700000000
   ```

5. **签名**：以待签串的 UTF-8 字节为消息、`secret` 的 UTF-8 字节为密钥，计算 HMAC-SHA256，取十六进制小写。

## 错误（422）

以下情况返回 `422 Unprocessable Entity`：

- 查询参数的**键**包含非 ASCII 字符（值允许非 ASCII，会按 UTF-8 百分号编码）；
- `timestamp` 不是十进制数字，或长度不为 10 位；
- 请求体缺少必填字段或字段类型错误。
