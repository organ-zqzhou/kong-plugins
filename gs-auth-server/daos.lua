---
--- 数据模型定义
--- Created by zqzhou.
--- DateTime: 2019/10/11 16:27
---
local typedefs = require "kong.db.schema.typedefs"

-- 令牌数据
local gauth_tokens = {
    name = "gauth_tokens",
    primary_key = { "id" },
    cache_key = { "access_token_client_id" },
    endpoint_key = "access_token_client_id",
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { access_token_client_id = { type = "string", required = true, unique = true }, },
        { access_token = { type = "string", required = true }, },
        { client_id = { type = "string", required = true }, },
        { expires_in = { type = "integer", required = true }, },
        { permissions = { type = "string", required = true }, },
        { created_at = typedefs.auto_timestamp_s }
    },
}

-- 令牌对应的客户端
local gauth_token_clients = {
    name = "gauth_token_clients",
    primary_key = { "id" },
    cache_key = { "access_token" },
    endpoint_key = "access_token",
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { access_token = { type = "string", required = true, unique = true }, },
        { client_ids = { type = "string", required = true }, },
        { created_at = typedefs.auto_timestamp_s }
    },
}

return {
    gauth_tokens,
    gauth_token_clients
}
