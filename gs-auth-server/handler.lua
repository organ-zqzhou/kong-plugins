local cjson = require "cjson"
local gsredis = require "kong.plugins.gs-auth.dao.redis"
local cluster = require "kong.plugins.gs-auth.dao.cluster"
local gsauth_service = require "kong.plugins.gs-auth.service.gauth"

local ngx = ngx
local kong = kong
local string = string
local find = string.find
local gsub = string.gsub
local ngx_re_gmatch = ngx.re.gmatch

local GsAuthServerHandler = {}

GsAuthServerHandler.PRIORITY = 1997
GsAuthServerHandler.VERSION = "1.0.0"

local HEADER = { ["Content-Type"] = "application/json; charset=utf-8",
                 ["cache-control"] = "no-store",
                 ["pragma"] = "no-cache" }

--- 服务内部错误响应
---
local function internal_server_error()
    return kong.response.exit(500, { message = "An unexpected error occurred" })
end

local function custome_server_error(status, body, header)
    return kong.response.exit(status, body, header)
end

--- 未认证错误响应
---
local function unauthorized_error(err_body)
    kong.response.exit(401, err_body, HEADER)
end

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

-- 递归权限点树
local convert_user_privilege_children_list

convert_user_privilege_children_list = function(user_privileges, children)
    for i, v in ipairs(children) do
        user_privileges[v.code] = v.expression

        if v.hasChildren then
            convert_user_privilege_children_list(user_privileges, v.children)
        end
    end
end

-- 递归权限点树 转化成 list
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

local function keep_redis_connection_alive(connection)
    -- 100个连接池，idle60秒
    local ok, err = connection:set_keepalive(60000, 100)

    if not ok then
        kong.log.err("[redis-keepalive-log] failed to set keepalive:", err)
    end
end

-- 获取用户令牌和权限
local function obtain_resource(conf, gsauth_client_id, token, index_id, connection)

    local user_privileges = {}

    -- check-token
    -- todo:先从缓存中校验，如果无再从gauth校验
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
        kong.log.err(status)
        return custome_server_error(status, res, HEADER)
    end

    local exp = cjson.decode(res).exp

    -- get privileges
    status, res, err = gsauth_service.obtain_user_privileges(conf, gsauth_client_id, token)

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
        client_id = gsauth_client_id,
        expires_in = exp,
        permissions = cjson.encode(user_privileges)
    }
end

local logout_policy = {
    cluster = function(conf, token)
        local ok = cluster.del_token_by_prefix(token)
        if not ok then
            return internal_server_error()
        end
    end,

    redis = function(conf, token)
        local connection = gsredis.connect_redis(conf)
        if not connection then
            return internal_server_error()
        end

        local ok = gsredis.del_token_by_prefix(connection, token)
        if not ok then
            return internal_server_error()
        end

        keep_redis_connection_alive(connection)
    end
}

--- 封装gsauth注销会话请求
local function do_logout(conf, token)
    -- 注销成功后删除 用户令牌和权限
    -- 这里要根据token找到refresh_token来把两个表的数据都删掉【tokens表要增加refresh_token字段】

    local request_path = kong.request.get_path_with_query()

    request_path = gsub(request_path, conf.gsauth_proxy_path, "")

    -- logout
    local status, res, err = gsauth_service.logout(conf, request_path, token)

    if err then
        kong.log.err(err)
        return internal_server_error()
    end

    -- 注销成功，gs-auth服务会响应302到登录页
    if status == 302 then

        logout_policy[conf.policy](conf, token)
        --if conf.policy == "redis" then
        --    logout_with_redis(conf, token)
        --elseif conf.policy == "cluster" then
        --    logout_with_cluster(conf, token)
        --end

        HEADER["Location"] = "http://" .. conf.gsauth_host .. ":" .. conf.gsauth_port .. conf.gsauth_proxy_path .. "/login?logout"
        return custome_server_error(status, res, HEADER)
        --return response_ok(res)
    end

    return custome_server_error(status, res, HEADER)
end

local heartbeat_proxy = {
    redis = function(conf, gsauth_client_id, token)
        local connection = gsredis.connect_redis(conf)
        if not connection then
            return internal_server_error()
        end

        local key = token .. ":" .. gsauth_client_id
        local token_table = gsredis.load_token(connection, key)

        if nil == token_table then

            local user_privileges, resource = obtain_resource(conf, gsauth_client_id, token, key, connection)

            local ok = gsredis.save_token(connection, resource)

            if not ok then
                keep_redis_connection_alive(connection)
                return internal_server_error()
            end
        end

        keep_redis_connection_alive(connection)

        return response_ok()
    end,
    cluster = function(conf, gsauth_client_id, token)

        local index_id = token .. ":" .. gsauth_client_id

        local token_table = cluster.load_token(index_id)

        if nil == token_table then

            local user_privileges, resource = obtain_resource(conf, gsauth_client_id, token, index_id, nil)

            local res, err = cluster.save_token(resource)

            if err then
                kong.log.err(err)
                return internal_server_error()
            end
        end

        return response_ok()
    end
}

--- 访问控制入口
--
-- @param 插件配置conf
function GsAuthServerHandler:access(conf)
    local request_path = kong.request.get_path()
    kong.log.notice(kong.request.get_path_with_query())

    -- 心跳检测 - 令牌是否过期
    if find(request_path, "/token/heartbeat") then
        local token = retrieve_parameters()["access_token"]
        local client_id = retrieve_parameters()["client_id"]

        if token == nil or client_id == nil then
            return custome_server_error(400, { message = "bad arguments" })
        end

        return heartbeat_proxy[conf.policy](conf, client_id, token)
        -- 对于gs-auth服务需要拦截器退出请求，用来注销会话
    elseif find(request_path, conf.gsauth_logout_path) then
        -- header或url携带领带
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
        return do_logout(conf, token)

    end

end

return GsAuthServerHandler
