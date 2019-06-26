---
--- kong.response.exit 响应封装
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:57
---

local kong = kong

local _M = {}

--
-- 服务内部错误 500
--
function _M.internal_server_error(err)
    kong.log.err(err)
    return kong.response.exit(500, "An unexpected error occurred")
end

--
-- 未经授权的错误 401
--
function _M.unauthorized_error(body)
    return kong.response.exit(401, body)
end

--
-- 响应重定向 302
--
function _M.send_redirect(body, headers)
    return kong.response.exit(302, body, headers)
end

--
-- 正常响应 200
--
function _M.ok(body, headers)
    return kong.response.exit(200, body, headers)
end

function _M:exit(status, body, headers)
    return kong.response.exit(status, body, headers)
end

return _M