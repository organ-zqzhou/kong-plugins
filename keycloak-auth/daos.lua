---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:55
---
local url = require "socket.url"

-- 令牌数据
local keycloak_auth_tokens = {
    primary_key = { "id" },
    name = "keycloak_auth_tokens",
    cache_key = { "tid" },
    ttl = true,
    fields = {
        { tid = { type = "string", required = true }, },
        { access_token = { type = "string", required = true }, },
        { expires_in = { type = "string", required = true }, },
        { refresh_token = { type = "string", required = true }, }
    },
}

-- 客户端数据
local keycloak_auth_clients = {
    primary_key = { "id" },
    name = "keycloak_auth_clients",
    endpoint_key = "id",
    cache_key = { "id" },
    ttl = true,
    fields = {
        { id = { type = "string", required = true }, },
        { client_id = { type = "string", required = true }, },
        { client_secret = { type = "string", required = true }, },
        { client_resources = { type = "string", required = true }, }
    },
}

-- 用户权限数据
local keycloak_auth_user_permissions = {
    primary_key = { "id" },
    name = "keycloak_auth_user_permissions",
    endpoint_key = "user_id",
    cache_key = { "user_id" },
    ttl = true,
    fields = {
        { id = { type = "string", required = true }, },
        { user_id = { type = "string", required = true }, },
        { client_id = { type = "string", required = true }, },
        { user_permissions = { type = "string", required = true }, }
    },
}

return {
    keycloak_auth_tokens,
    keycloak_auth_clients,
    keycloak_auth_user_permissions,
}
