"""请求签名 API（单文件）。

规范化查询串 + 四行待签串（方法 / 请求路径 / 规范化查询串 / 时间戳），
使用 HMAC-SHA256 计算签名，返回十六进制小写。
"""

import hashlib
import hmac
import re
from typing import List
from urllib.parse import quote

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Request Signing API")

# 十位十进制时间戳（仅 ASCII 数字）
_TIMESTAMP_RE = re.compile(r"[0-9]{10}")


def pct_encode(s: str) -> str:
    """RFC 3986 百分号编码：保留 A-Z a-z 0-9 与 -_.~，
    其余字符按 UTF-8 字节编码为 %XX（空格为 %20，不是 +）。"""
    return quote(s, safe="-_.~", encoding="utf-8", errors="strict")


class Param(BaseModel):
    """单个查询参数键值对（允许重复键，由请求数组顺序外的排序规则决定次序）。"""

    key: str
    value: str = ""

    @field_validator("key")
    @classmethod
    def key_must_be_ascii(cls, v: str) -> str:
        if not v.isascii():
            raise ValueError("key 仅允许 ASCII 字符")
        return v


class SignRequest(BaseModel):
    method: str
    path: str
    params: List[Param] = Field(default_factory=list)
    secret: str
    timestamp: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def coerce_timestamp(cls, v):
        # 兼容 JSON 数字形式的时间戳，统一按字符串校验
        if isinstance(v, int) and not isinstance(v, bool):
            return str(v)
        return v

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_10_digits(cls, v: str) -> str:
        if not isinstance(v, str) or not _TIMESTAMP_RE.fullmatch(v):
            raise ValueError("timestamp 必须为十位十进制数字")
        return v


class SignResponse(BaseModel):
    canonical_query: str
    signature: str


def canonical_query_string(params: List[Param]) -> str:
    """按键的 UTF-8 字节序升序，键相同按值的 UTF-8 字节序升序；
    键值分别做 RFC 3986 编码后以 k=v 形式用 & 连接，空值只保留键。"""
    ordered = sorted(
        params,
        key=lambda p: (p.key.encode("utf-8"), p.value.encode("utf-8")),
    )
    parts = []
    for p in ordered:
        encoded_key = pct_encode(p.key)
        if p.value == "":
            parts.append(encoded_key)
        else:
            parts.append(f"{encoded_key}={pct_encode(p.value)}")
    return "&".join(parts)


@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest) -> SignResponse:
    canonical = canonical_query_string(req.params)
    string_to_sign = "\n".join([req.method, req.path, canonical, req.timestamp])
    signature = hmac.new(
        req.secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return SignResponse(canonical_query=canonical, signature=signature)
