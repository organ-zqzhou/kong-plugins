local cjson = require "cjson"
local utils = require "kong.tools.utils"
local cluster = require "kong.plugins.gs-auth.dao.cluster"
local gsredis = require "kong.plugins.gs-auth.dao.redis"
local gsauth_service = require "kong.plugins.gs-auth.service.gauth"

local ngx = ngx
local kong = kong
local table = table
local string = string
local find = string.find
local gsub = string.gsub
local insert = table.insert
local concat = table.concat
local ngx_re_gmatch = ngx.re.gmatch
local table_contains = utils.table_contains

local GsAuthHandler = {}

GsAuthHandler.PRIORITY = 1998
GsAuthHandler.VERSION = "1.0.0"

local HEADER = { ["Content-Type"] = "application/json; charset=utf-8",
                 ["cache-control"] = "no-store",
                 ["pragma"] = "no-cache" }

--- 服务内部错误响应
---
local function internal_server_error()
    return kong.response.exit(500, { message = "An unexpected error occurred" })
end

--- 自定义错误响应
---
local function custome_server_error(status, body, header)
    return kong.response.exit(status, body, header)
end

--- 未认证错误响应
---
local function unauthorized_error(err_body)
    kong.response.exit(401, err_body, HEADER)
end

--- 成功响应
---
local function response_ok(body)
    kong.response.exit(200, body, HEADER)
end

--- 获取Authorization头数据
--
-- 根据传入的正则表达式获取Authorization头数据
-- @param 正则表达式
-- @return Authorization头数据
local function retrieve_auth_header()
    local token
    local authorization_header = kong.request.get_header("Authorization")
    if authorization_header then
        local iterator = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if iterator then
            local m, err = iterator()
            if err then
                kong.log.err("retrieve_auth_header(): error occurred...", err)
                return internal_server_error()
            end

            if m and #m > 0 then
                token = m[1]
            end
        end
    end

    return token
end

--- 获取请求中的参数
--
-- 从GET、POST、PUT、PATCH类型的请求中获取参数的集合
-- @return 包含参数名和参数值的table
local function retrieve_parameters()
    local uri_args = kong.request.get_query()
    local method = kong.request.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        local body_args = kong.request.get_body()

        return kong.table.merge(uri_args, body_args)
    end

    return uri_args
end

--- 匹配资源
--
-- @param 待匹配路径
-- @param 资源集合
-- @return 匹配到的资源名称
local function matching_resources(path, resources)
    local shoot_resource

    if nil ~= resources then
        for i, v in pairs(resources) do
            if string.find(path, v) then
                shoot_resource = v
                break
            end

            if shoot_resource then
                break
            end
        end
    end

    return shoot_resource
end

--- 递归权限点树
--
local convert_user_privilege_children_list
convert_user_privilege_children_list = function(user_privileges, children)
    for i, v in ipairs(children) do
        user_privileges[v.code] = v.expression

        if v.hasChildren then
            convert_user_privilege_children_list(user_privileges, v.children)
        end
    end
end

--- 递归权限点树 转化成 list
--
local function convert_user_privilege_list(tree_res)
    local user_privileges = {}

    tree_res = cjson.decode(tree_res)

    for i, v in ipairs(tree_res) do
        user_privileges[v.code] = v.expression
        if v.hasChildren then
            convert_user_privilege_children_list(user_privileges, v.children)
        end
    end

    return user_privileges
end

--- redis连接keep alive
--
local function keep_redis_connection_alive(connection)
    -- 100个连接池，idle60秒
    local ok, err = connection:set_keepalive(60000, 100)

    if not ok then
        kong.log.err("[redis-keepalive-log] failed to set keepalive:", err)
    end
end

--- 获取用户令牌和权限
--
local function obtain_resource(conf, token, index_id, connection)

    local user_privileges = {}

    -- check-token
    -- 这里默认每访问一个业务系统校验一次令牌
    local status, res, err = gsauth_service.check_token(conf, token)

    if err then
        kong.log.err(err)
        if connection then
            keep_redis_connection_alive(connection)
        end
        return internal_server_error()
    end

    if cjson.decode(res).error ~= nil then
        if connection then
            keep_redis_connection_alive(connection)
        end
        return custome_server_error(401, res, HEADER)
    end

    if status ~= 200 then
        if connection then
            keep_redis_connection_alive(connection)
        end
        return custome_server_error(status, res, HEADER)
    end

    local exp = cjson.decode(res).exp

    -- get privileges
    status, res, err = gsauth_service.obtain_user_privileges(conf, conf.gsauth_client_id, token)

    if err then
        kong.log.err(err)
        if connection then
            keep_redis_connection_alive(connection)
        end
        return internal_server_error()
    end

    if status ~= 200 then
        if connection then
            keep_redis_connection_alive(connection)
        end
        return custome_server_error(status, res, HEADER)
    end

    if nil ~= res then
        user_privileges = convert_user_privilege_list(res)
    end

    return user_privileges, {
        access_token_client_id = index_id,
        access_token = token,
        client_id = conf.gsauth_client_id,
        expires_in = exp,
        permissions = cjson.encode(user_privileges)
    }
end

--- 访问控制策略
--
local access_policy = {
    redis = function(conf, token)
        local connection = gsredis.connect_redis(conf)
        if not connection then
            return internal_server_error()
        end

        local user_privileges = {}

        local key = token .. ":" .. conf.gsauth_client_id
        local token_table = gsredis.load_token(connection, key)

        if nil == token_table then

            local resource
            user_privileges, resource = obtain_resource(conf, token, key, connection)

            local ok = gsredis.save_token(connection, resource)

            if not ok then
                keep_redis_connection_alive(connection)
                return internal_server_error()
            end
        else
            user_privileges = cjson.decode(token_table.permissions)
        end

        keep_redis_connection_alive(connection)

        return user_privileges
    end,
    cluster = function(conf, token)

        local user_privileges = {}

        local index_id = token .. ":" .. conf.gsauth_client_id

        local token_table = cluster.load_token(index_id)

        if nil == token_table then

            local resource
            user_privileges, resource = obtain_resource(conf, token, index_id, nil)

            local res, err = cluster.save_token(resource)

            if err then
                kong.log.err(err)
                return internal_server_error()
            end
        else
            if token_table.expires_in ~= nil and (os.time() > tonumber(token_table.expires_in)) then
                local res, err = cluster.del_token(token_table.id)
                if err then
                    return internal_server_error()
                end

                return unauthorized_error({
                    error = "invalid_token",
                    error_description = "Token has expired"
                })
            end

            user_privileges = cjson.decode(token_table.permissions)
        end

        return user_privileges
    end
}

--- 刷新权限策略
--
local flush_policy = {
    redis = function(conf, token)
        local connection = gsredis.connect_redis(conf)
        if not connection then
            return internal_server_error()
        end

        local key = token .. ":" .. conf.gsauth_client_id
        local token_table = gsredis.load_token(connection, key)

        if nil == token_table then
            keep_redis_connection_alive(connection)
            return custome_server_error(202, { message = "No privileges will be flushed" }, HEADER)
        end

        -- 刷新权限
        local status, res, err = gsauth_service.obtain_user_privileges(conf, conf.gsauth_client_id, token)

        if err then
            kong.log.err(err)
            keep_redis_connection_alive(connection)
            return internal_server_error()
        end

        if status ~= 200 then
            keep_redis_connection_alive(connection)
            return custome_server_error(status, res, HEADER)
        end

        local user_privileges = {}
        if nil ~= res then
            user_privileges = convert_user_privilege_list(res)
        end

        local resource = {
            access_token = token,
            client_id = conf.gsauth_client_id,
            expires_in = token_table.expires_in,
            permissions = cjson.encode(user_privileges)
        }

        local ok = gsredis.save_token(connection, resource)

        if not ok then
            keep_redis_connection_alive(connection)
            return internal_server_error()
        end

        keep_redis_connection_alive(connection)

        return response_ok()
    end,

    cluster = function(conf, token)

        local index_id = token .. ":" .. conf.gsauth_client_id

        local token_table = cluster.load_token(index_id)

        if nil == token_table then
            return custome_server_error(202, { message = "No privileges will be flushed" }, HEADER)
        end

        -- 刷新权限
        local status, res, err = gsauth_service.obtain_user_privileges(conf, conf.gsauth_client_id, token)

        if err then
            kong.log.err(err)
            return internal_server_error()
        end

        if status ~= 200 then
            return custome_server_error(status, res, HEADER)
        end

        local user_privileges = {}
        if nil ~= res then
            user_privileges = convert_user_privilege_list(res)
        end

        token_table.permissions = cjson.encode(user_privileges)

        res, err = cluster.update_token(token_table)

        if err then
            kong.log.err(err)
            return internal_server_error()
        end

        return response_ok()
    end
}

--- 注销令牌策略
--
local invalidate_policy = {
    cluster = function(conf, token)
        local ok = cluster.del_token_by_prefix(token)
        if not ok then
            return internal_server_error()
        end
        return response_ok()
    end,

    redis = function(conf, token)
        local connection = gsredis.connect_redis(conf)
        if not connection then
            return internal_server_error()
        end

        local ok = gsredis.del_token_by_prefix(connection, token)
        if not ok then
            keep_redis_connection_alive(connection)
            return internal_server_error()
        end

        keep_redis_connection_alive(connection)
        return response_ok()
    end
}

--- 访问控制入口
-- authn_whitelist：认证白名单，不需要经过认证即可访问（可不携带令牌访问）
-- authz_whitelist：授权白名单，需要经过认证但不用校验权限（需携带令牌）
--
-- 所有请求先经过该逻辑处理，联合gs-auth进行权限检查
-- @param 插件配置conf
function GsAuthHandler:access(conf)
    local request_path = kong.request.get_path()
    local authn_whitelist = conf.authn_whitelist or {}

    local is_authn_whitelist = false
    for i = 1, #authn_whitelist do
        if find(request_path, authn_whitelist[i]) then
            is_authn_whitelist = true
            break
        end
    end

    -- 非白名单请求
    if not is_authn_whitelist then

        -- header或url携带令牌
        local token = retrieve_auth_header()
        if not token then
            token = retrieve_parameters()["access_token"]
        end

        -- 未携带令牌 响应401
        if not token then
            return unauthorized_error({
                error = "unauthorized",
                error_description = "Full authentication is required to access this resource"
            })
        end

        -- 如果有令牌权限缓存，则判断是否是刷新或者注销请求
        if find(request_path, "/privileges/flush") then
            -- 刷新令牌请求
            return flush_policy[conf.policy](conf, token)
        elseif find(request_path, "/token/invalidate") then
            -- 注销令牌请求
            return invalidate_policy[conf.policy](conf, token)
        end

        local user_privileges = access_policy[conf.policy](conf, token)

        local authz_whitelist = conf.authz_whitelist or {}
        local is_authz_whitelist = false
        for i = 1, #authz_whitelist do
            if find(request_path, authz_whitelist[i]) then
                is_authz_whitelist = true
                break
            end
        end

        if not is_authz_whitelist then
            -- 校验用户权限
            if not matching_resources(request_path, user_privileges) then
                return kong.response.exit(403, {
                    error = "forbidden",
                    error_description = "The token has no right to access this resource"
                }, { ["Content-Type"] = "application/json; charset=utf-8",
                     ["cache-control"] = "no-store",
                     ["pragma"] = "no-cache" })
            end
        end
    end
end

return GsAuthHandler
