---
--- 权限判断
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:02
---
local cjson = require "cjson"
local utils = require "kong.tools.utils"
local constants = require "kong.constants"
local timestamp = require "kong.tools.timestamp"
local zhttp = require "kong.plugins.keycloak-auth.utils.http"
local constants = require "kong.plugins.keycloak-auth.constants"
local jwt_decoder = require "kong.plugins.keycloak-auth.utils.jwt"

local kong = kong

local _M = {}

function _M.access(conf)
    -- 获取token、用户id和client_id
    local token = "测试用，这里使用postman请求得来即可"
    local client_id = ""
    local user_id = kong.request.get_header("X-Authenticated-User-ID")
    local user_name = kong.request.get_header("X-Authenticated-User-Name")

    -- 先获取client_id下的所有资源
    -- 应该先从缓存取，缓存没有则从数据库取，如果数据库也没有就需要请求认证中心获取一次然后缓存下来使用
    -- 缓存表[client_id, client_resources]，其中client_resources是资源集合的json字符串
    -- 通过逐一匹配，获取当前请求地址的对应资源 shoot_resource

    -- 使用client_id和token获取用户的权限数据 user_resources
    -- 应该先从缓存取，缓存没有则从数据库取，如果数据库也没有就需要请求认证中心获取一次然后缓存下来使用
    -- 缓存表[user_id, client_id, user_resources]，其中user_resources是资源集合的json字符串
    -- 使用shoot_resource逐一匹配用户的user_resources

    -- 如果匹配则通过
    -- 否则响应403无权限
end

return _M