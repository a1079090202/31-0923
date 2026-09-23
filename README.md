# 请求签名 API

基于 FastAPI 的单文件请求签名服务（`main.py`），按规范化查询串生成 HMAC-SHA256 签名。

## 启动

端口为 **8000**：

```bash
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

安装依赖：

```bash
pip install -r requirements.txt
```

## 接口

`POST /sign`

请求体：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `method` | string | HTTP 方法（如 `GET`、`POST`） |
| `path` | string | 请求路径（如 `/api/v1/users`） |
| `params` | 数组 | 查询参数数组，每项 `{"key": ..., "value": ...}`，允许重复键，`value` 可省略（视为空串） |
| `secret` | string | HMAC 密钥 |
| `timestamp` | string | 十位十进制时间戳（如 `1700000000`） |

响应体：

```json
{ "canonical_query": "...", "signature": "..." }
```

### 签名规则

1. 参数按 **键的字节序**（UTF-8 编码字节）升序排列；键相同时按 **值的字节序** 升序排列。
2. 键与值均做 RFC 3986 百分号编码：空格编码为 `%20`，字母、数字及 `-_.~` 不编码，非 ASCII 字符按 UTF-8 字节编码。
3. 以 `k=v` 形式、`&` 连接；值为空串时只输出键（`k`）。
4. 待签串为以下四行以换行符 `\n` 连接：

   ```
   <method>
   <path>
   <canonical_query>
   <timestamp>
   ```

5. 签名为 `HMAC-SHA256(secret, 待签串)` 的十六进制小写。

### 错误（HTTP 422）

- 参数键含非 ASCII 字符；
- 时间戳不是十进制数字，或长度不为 10；
- 请求体缺少必需字段或类型不符。

## 示例

```bash
curl -s http://127.0.0.1:8000/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "path": "/api/x",
    "params": [
      {"key": "b", "value": "2"},
      {"key": "a", "value": ""},
      {"key": "a", "value": "1"}
    ],
    "secret": "s3cret",
    "timestamp": "1700000000"
  }'
```

响应：

```json
{
  "canonical_query": "a&a=1&b=2",
  "signature": "402e57e69439ffe29230c58cfe6156ea064a2251178e6cf84546020e7ac24cb0"
}
```
