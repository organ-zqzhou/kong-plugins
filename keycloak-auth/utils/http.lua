---
--- HTTP请求工具类
--- Created by zqzhou.
--- DateTime: 2019/6/25 上午10:14
---
local zhttp = require "resty.http"

local _M = {}

--
-- 发送GET请求
-- return status, body, err_
--
function _M:http_get_client(url, headers, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    local res, err_ = httpc:request_uri(url, {
        method = "GET",
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    if not res then
        return res.status, nil, err_
    else
        if res.status == 200 then
            return res.status, res.body, err_
        else
            return res.status, nil, err_
        end
    end
end

--
-- 发送POST请求
-- return status, body, err_
--
function _M:http_post_client(url, headers, body, timeout)
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

    if not res then
        return res.status, nil, err_
    else
        if res.status == 200 then
            return 200, res.body, err_
        else
            if res.status == 400 then
                return 400, res.body, err_
            else
                return res.status, nil, err_
            end
        end
    end
end

return _M