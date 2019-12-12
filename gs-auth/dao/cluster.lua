local utils = require "kong.tools.utils"

local kong = kong
local split = utils.split

local function load_db_by_index_id(index_id)
    local token, err = kong.db.gauth_tokens:select_by_access_token_client_id(index_id)
    if err then
        return nil, err
    end

    return token, nil
end

local function load_token_clients(access_token)
    local token, err

    local load_db_by_access_token = function(access_token)
        local token, err = kong.db.gauth_token_clients:select_by_access_token(access_token)
        if err then
            return nil, err
        end

        return token, nil
    end

    local cache_key = kong.db.gauth_token_clients:cache_key(access_token)
    token, err = kong.cache:get(cache_key, nil, load_db_by_access_token, access_token)
    if err then
        kong.log.err(err)
        return nil, err
    end

    return token, nil
end

return {
    save_token = function(token)
        -- mlcache max ttl 100000000
        local expires_in = token.expires_in ~= nil and token.expires_in or (os.time() + 100000000)
        local ttl = expires_in - os.time()
        local res, err = kong.db.gauth_tokens:insert(token, {
            ttl = ttl
        })
        if err then
            kong.log.err(err)
            return nil, err
        end

        -- ??token?client???
        local token_clients, err_ = load_token_clients(token.access_token)
        if err_ then
            kong.log.warn(err_)
        end

        local clients
        if nil == token_clients then
            clients = token.client_id
            local insert, err = kong.db.gauth_token_clients:insert({
                access_token = token.access_token,
                client_ids = clients
            }, {
                ttl = ttl
            })

            if err then
                kong.log.err(err)
                return nil, err
            end
        else
            clients = token_clients.client_ids .. "," .. token.client_id
            local upsert, err = kong.db.gauth_token_clients:upsert({
                id = token_clients.id
            }, {
                access_token = token.access_token,
                client_ids = clients
            }, {
                ttl = ttl
            })

            if err then
                kong.log.err(err)
                return nil, err
            end
        end

        return res, err
    end,
    load_token = function(index_id)
        local token, err

        if index_id then
            local cache_key = kong.db.gauth_tokens:cache_key(index_id)
            token, err = kong.cache:get(cache_key, nil, load_db_by_index_id, index_id)
            if err then
                kong.log.err(err)
                return nil, err
            end

        end

        return token, nil
    end,
    del_token = function(id)
        local res, err = kong.db.gauth_tokens:delete({ id = id })

        if err then
            kong.log.err(err)
            return nil, err
        end

        return res, err
    end,
    update_token = function(token)
        local upsert, err = kong.db.gauth_tokens:upsert({
            id = token.id
        }, token)

        if err then
            kong.log.err(err)
            return false, err
        end

        return true
    end,
    del_token_by_prefix = function(access_token)

        local token_clients, err_ = load_token_clients(access_token)
        if err_ then
            kong.log.warn(err_)
        end

        if nil == token_clients then
            return true
        end

        local token_parts = split(token_clients.client_ids, ",")

        local res, err = kong.db.gauth_token_clients:delete_by_access_token(access_token)

        if err then
            kong.log.err(err)
            return false, err
        end

        for i, v in pairs(token_parts) do
            res, err = kong.db.gauth_tokens:delete_by_access_token_client_id(access_token .. ":" .. v)

            if err then
                kong.log.err(err)
                return false, err
            end
        end

        return true
    end,
}
