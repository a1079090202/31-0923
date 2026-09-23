"""单文件请求签名 API（FastAPI）。

规则：
- 查询参数为键值对数组，允许重复键；
- 按键的字节序升序排列，键相同按值的字节序升序排列；
- 键与值按 RFC 3986 百分号编码（空格为 %20，字母数字及 -_.~ 不编码）；
- 以 & 连接为 k=v，空值只保留键；
- 待签串 = 方法 / 请求路径 / 规范化查询串 / 时间戳，四行以换行连接；
- 签名 = HMAC-SHA256(secret, 待签串) 的十六进制小写。
"""

import hashlib
import hmac
import re
from urllib.parse import quote

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Request Signing API")

_TIMESTAMP_RE = re.compile(r"[0-9]{10}")


class ParamPair(BaseModel):
    key: str
    value: str = ""


class SignRequest(BaseModel):
    method: str
    path: str
    params: list[ParamPair] = Field(default_factory=list)
    secret: str
    timestamp: str


class SignResponse(BaseModel):
    canonical_query: str
    signature: str


def _percent_encode(text: str) -> str:
    # safe="" 时仅字母、数字及 _ . - ~ 不编码；空格编码为 %20，
    # 非 ASCII 字符按 UTF-8 字节逐字节百分号编码。
    return quote(text, safe="")


def _canonical_query(params: list[ParamPair]) -> str:
    ordered = sorted(
        params,
        key=lambda p: (p.key.encode("utf-8"), p.value.encode("utf-8")),
    )
    parts: list[str] = []
    for pair in ordered:
        encoded_key = _percent_encode(pair.key)
        if pair.value == "":
            parts.append(encoded_key)
        else:
            parts.append(f"{encoded_key}={_percent_encode(pair.value)}")
    return "&".join(parts)


@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest) -> SignResponse:
    for pair in req.params:
        if not pair.key.isascii():
            raise HTTPException(
                status_code=422,
                detail=f"参数键必须为 ASCII 字符: {pair.key!r}",
            )

    if not _TIMESTAMP_RE.fullmatch(req.timestamp):
        raise HTTPException(
            status_code=422,
            detail="时间戳必须为 10 位十进制数字",
        )

    canonical_query = _canonical_query(req.params)
    string_to_sign = "\n".join(
        [req.method, req.path, canonical_query, req.timestamp]
    )
    signature = hmac.new(
        req.secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return SignResponse(
        canonical_query=canonical_query,
        signature=signature,
    )
