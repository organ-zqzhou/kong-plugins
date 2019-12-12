local redis = require "resty.redis"
local cjson = require "cjson"

local kong = kong

return {
    connect_redis = function(conf)
        local red = redis:new()
        red:set_timeout(conf.redis_timeout)

        local sock_opts = {}
        sock_opts.pool = conf.redis_database and
                conf.redis_host .. ":" .. conf.redis_port ..
                        ":" .. conf.redis_database

        local ok, err = red:connect(conf.redis_host, conf.redis_port, sock_opts)

        if not ok then
            kong.log.err("[redis-log] failed to connect to redis:", err)
            return
        end

        if conf.redis_password then
            local ok, err = red:auth(conf.redis_password)

            if not ok then
                kong.log.err("[redis-log] failed to auth:", err)
                return
            end
        end

        return red
    end,
    save_token = function(connection, token)
        local key = token.access_token .. ":" .. token.client_id

        local value = {
            permissions = token.permissions,
            expires_in = token.expires_in
        }
        local ok, err = connection:set(key, cjson.encode(value))

        if err then
            kong.log.err("[redis-log] failed to save to redis:", err)
            return false, err
        end

        if token.expires_in then
            ok, err = connection:expire(key, token.expires_in - os.time())
            if err then
                kong.log.err("[redis-log] failed to set expire:", err)
                return false, err
            end
        end

        return true
    end,
    load_token = function(connection, key)
        local tokens, err = connection:keys(key)
        if err then
            kong.log.err("[redis-log] failed to get keys:", err)
            return nil, err
        end

        if next(tokens) == nil then
            return nil, (key .. " not exists")
        end

        local res, err = connection:get(key)
        if err then
            kong.log.err("[redis-log] failed to get key:", err)
            return nil, err
        end

        return cjson.decode(res)
    end,
    del_token = function(connection, key)
        connection:init_pipeline()
        connection:del(key)

        local ok, err = connection:commit_pipeline()
        if not ok then
            kong.log.err("[redis-log] failed to del:", err)
            return false, err
        end

        return true
    end,
    del_token_by_prefix = function(connection, access_token)
        local tokens, err = connection:keys(access_token .. "*")
        if err then
            kong.log.err("[redis-log] failed to get keys:", err)
            return nil, err
        end

        if next(tokens) == nil then
            kong.log.warn(access_token .. " not exists")
            return true
        end

        connection:init_pipeline()

        for i, v in pairs(tokens) do
            connection:del(v)
        end

        local ok, err = connection:commit_pipeline()

        if not ok then
            kong.log.err("[redis-log] failed to del:", err)
            return false, err
        end

        return true
    end,
}