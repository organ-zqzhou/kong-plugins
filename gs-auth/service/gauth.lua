local zhttp = require "resty.http"

local string = string
local gsub = string.gsub

--- ??????
local function get_privileges_api(conf, gsauth_client_id)
    local privileges_api = "http://" .. conf.gsauth_host .. ":" .. conf.gsauth_port .. conf.gsauth_privileges_path
    return gsub(privileges_api, "%{.*%}", gsauth_client_id)
end

--- ????????
local function get_check_token_api(conf)
    return "http://" .. conf.gsauth_host .. ":" .. conf.gsauth_port .. conf.gsauth_check_token_path
end

--- ????????
local function get_api_prefix(conf)
    return "http://" .. conf.gsauth_host .. ":" .. conf.gsauth_port
end

--- ??GET??
--
-- @param url
-- @param headers
-- @param timeout
-- @return status, body, err_
local function http_get_client(url, headers, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Accept"] = "application/json"

    local res, err_ = httpc:request_uri(url, {
        method = "GET",
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    return res.status, res.body, err_
end

--- ??POST??
--
-- @param url
-- @param headers
-- @param timeout
-- @return status, body, err_
local function http_post_client(url, headers, body, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    local res, err_ = httpc:request_uri(url, {
        method = "POST",
        body = body,
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    return res.status, res.body, err_
end

return {
    obtain_user_privileges = function(conf, gsauth_client_id, access_token)
        local headers = { ["Authorization"] = "Bearer " .. access_token }

        local privileges_api = get_privileges_api(conf, gsauth_client_id)
        return http_get_client(privileges_api, headers, 6000)
    end,

    check_token = function(conf, access_token)
        local headers = { ["Authorization"] = "Bearer " .. access_token }

        local check_token_api = get_check_token_api(conf)
        return http_get_client(check_token_api, headers, 6000)
    end,

    refresh_token = function(conf, request_path)
        local refresh_token_api = get_api_prefix(conf) .. request_path
        return http_post_client(refresh_token_api, nil, nil, 6000)
    end,
    logout = function(conf, request_path, access_token)
        local headers = { ["Authorization"] = "Bearer " .. access_token }

        local logout_api = get_api_prefix(conf) .. request_path

        return http_get_client(logout_api, headers, 6000)
    end
}