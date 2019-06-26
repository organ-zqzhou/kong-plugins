---
--- 认证处理
--- Created by zqzhou.
--- DateTime: 2019/6/25 上午10:27
---
local cjson = require "cjson"
local utils = require "kong.tools.utils"
local timestamp = require "kong.tools.timestamp"
local rsa_keys = require "kong.plugins.keycloak-auth.auth.keys"
local zhttp = require "kong.plugins.keycloak-auth.utils.http"
local exit = require "kong.plugins.keycloak-auth.utils.exit"
local constants = require "kong.plugins.keycloak-auth.constants"
local jwt_decoder = require "kong.plugins.keycloak-auth.utils.jwt"

local kong = kong
local type = type
local sub = string.sub
local find = string.find
local concat = table.concat
local table = table
local unpack = unpack
local tostring = tostring
local split = utils.split
local strip = utils.strip
local encode_args = utils.encode_args
local random_string = utils.random_string
local table_contains = utils.table_contains

local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local ngx_decode_args = ngx.decode_args
local ngx_re_gmatch = ngx.re.gmatch
local ngx_encode_base64 = ngx.encode_base64

local _M = {}

local rsa_private_key = rsa_keys.rsa_private_key
local rsa_public_key = rsa_keys.rsa_public_key

local kc_token = [[
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOMnd1bkQySFQ2YVYyTndOOHVyZjZkOU5NSmNFWVVLZjZXZHlsNGFicEV3In0.eyJqdGkiOiIwZmIzNTNhZC1hZDY3LTQyYzAtOTFkNy0yZTg5NGY2MGRjMmEiLCJleHAiOjE1NjExMDI5MjUsIm5iZiI6MCwiaWF0IjoxNTYxMTAyNjI1LCJpc3MiOiJodHRwOi8vMTkyLjE2OC42OS4xODc6ODA4MC9hdXRoL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsiRE9DLXJlYWxtIiwic3ByaW5nLWJvb3Qta2V5Y2xvYWstcmVhbG0iLCJ0ZXN0LXJlYWxtIiwibWFzdGVyLXJlYWxtIiwiYWNjb3VudCIsInBob3Rvei1yZWFsbSJdLCJzdWIiOiI4MjQ1NTNmYS00ZDI0LTQzMTYtOWI2Ni1kMzhlYTllNTZmYzciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJrb25nIiwiYXV0aF90aW1lIjoxNTYxMTAxNjE0LCJzZXNzaW9uX3N0YXRlIjoiNzQzOGVkM2ItYTRjYi00MDRiLTk0YzQtNGJmM2VmZWY1NjY4IiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vMTkyLjE2OC4yMjIuMTMyOjgwMDAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsIm9mZmxpbmVfYWNjZXNzIiwiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7IkRPQy1yZWFsbSI6eyJyb2xlcyI6WyJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsInZpZXctcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfSwic3ByaW5nLWJvb3Qta2V5Y2xvYWstcmVhbG0iOnsicm9sZXMiOlsidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJ2aWV3LXJlYWxtIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sInRlc3QtcmVhbG0iOnsicm9sZXMiOlsidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJ2aWV3LXJlYWxtIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sIm1hc3Rlci1yZWFsbSI6eyJyb2xlcyI6WyJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsInZpZXctcmVhbG0iLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19LCJwaG90b3otcmVhbG0iOnsicm9sZXMiOlsidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJ2aWV3LXJlYWxtIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImxvY2FsZSI6InpoLUNOIn0.J58f_GDDe67ii8OQJCvHTgiAQIONDT0ax_DQbshYyHi5YQBZr_6V_4hq86tVOO-ip_aT42_NfRkjt99pMGdwrziIPZUXFetd8EWELI5aSIlf25wrxMtbADgK0g_ZtBPvuCZ1c-cp31PeRyK3ojDQD9gIIPQNcUel_jLaR7j2Jsu8ToRxjlIhDjxaTMWjR_6SmLQQVIfkAfD4ha9099RSEJNjdpvPMDwFlxFT504BdCBB9HHEEDm5FWjvvO0GaEvKkL0IWazj8N55ZT5BPT3h8DJGrBYCmoMH370y6V8WpOq1h0zDqDDfLmrmIvp3-zVPHIJHAvZwTwoXkUVA39W0lg
]]

--
-- 从请求中获取参数
--
local function retrieve_parameters()
    local uri_args = kong.request.get_query()
    local method = kong.request.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        local body_args = kong.request.get_body()

        return kong.table.merge(uri_args, body_args)
    end

    return uri_args
end

--
-- 获取重定向到登录的跳转地址
--
local function retrieve_redirect_uri()
    return "test"
end

--
-- 重定向到认证中心要求登录
--
local function redirect_to_auth(client_uri, client_id, conf)

    local response_type = "code"
    local redirect_uri = conf.kong_auth_url
    local state = client_uri
    local auth_url = conf.auth_url

    local redirect_to_auth = auth_url .. "?response_type=" .. response_type .. "&client_id=" .. client_id .. "&redirect_uri=" .. redirect_uri .. "&state=" .. state .. "&login=true&scope=openid"

    local x_requested_with = kong.request.get_header("X-Requested-With")

    if x_requested_with and x_requested_with == "XMLHttpRequest" then

        local result = {
            status = 302,
            redirect_uri = redirect_to_auth
        }

        return exit:ok(cjson_encode(result), {
            ["Content-Type"] = "application/json; charset=utf-8",
            ["Redirect-To"] = redirect_to_auth
        })
    end
    return exit:send_redirect({}, { ["Location"] = redirect_to_auth })
end

--
-- 从请求中获取令牌
--
local function retrieve_token()
    local token = {}
    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if iterator then
            local m, err = iterator()
            if err then
                return exit:internal_server_error(err)
            end

            if m and #m > 0 then
                token = m[1]
            end
        end
    end

    return token
end

--
-- 重新签名
-- 使用RSA私钥对Keycloak签发的令牌重新签名
-- 即：替换signature部分
-- 返回：重签名后的令牌
--
local function re_signature(token)
    local result, pos, str, div, len = {}, 0, token, ".", 3

    local iter = function()
        return find(str, div, pos, true)
    end

    for st, sp in iter do
        result[#result + 1] = sub(str, pos, st - 1)
        pos = sp + 1
        len = len - 1
        if len <= 1 then
            break
        end
    end

    result[#result + 1] = sub(str, pos)

    local header_64, claims_64, signature_64 = unpack(result)

    local re_sig_64, err = jwt_decoder:sign_signature_with(constants.ALGORITHM, header_64 .. "." .. claims_64, rsa_private_key)
    if err then
        return exit:internal_server_error(err)
    end

    local segments = {
        header_64,
        claims_64,
        re_sig_64
    }

    return concat(segments, ".")

end

--
-- 根据令牌id还原签名
-- 即：替换回原Keycloak签发的令牌的签名 不用这么玩，直接根据tid找回原token即可
--
local function restore_signature(tid)
    local token = kc_token
    return token
end

--
-- 根据tid从仓库获取access_token和refresh_token
--
local function get_token_by_tid(tid)
    local access_token, refresh_token = "", ""
    return access_token, refresh_token
end

--
-- 校验token，并返回由Keycloak签发的有效token
--
local function verify_token(token)

    -- 解码token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return exit:unauthorized_error({ message = "Invalid token: " .. tostring(err), redirect_uri = "" })
    end

    -- 公钥验签
    local verify, err = jwt:verify_signature(constants.ALGORITHM, rsa_public_key)
    if err or not verify then
        return exit:unauthorized_error({ message = "Invalid token: invalid signature", redirect_uri = "" })
    end

    -- 转发之前，替换回Keycloak签发的令牌
    local kc_token = restore_signature(jwt.claims.jti)

    return jwt, kc_token
end

--
-- 处理来自认证中心重定向过来的请求
-- 使用code换取token
--
local function hand_redirect_request(conf)
    local parameters = retrieve_parameters()
    local code = parameters[constants.CODE]

    if nil == code then
        return exit:unauthorized_error({ message = "No code found", redirect_uri = "" })
    end

    -- 使用state代表客户端地址吧！
    local state = parameters[constants.STATE]

    local body = {
        [constants.GRANT_TYPE] = constants.GRANT_AUTHORIZATION_CODE,
        [constants.CODE] = code,
        [constants.REDIRECT_URI] = conf.kong_host .. conf.kong_redirect_path
    }

    local client_id = "kong"
    local client_secret = "b121b1e8-8926-4474-a0fd-abf8f9c2a1fd"

    local client_credentials = ngx_encode_base64(client_id .. ":" .. client_secret)

    local headers = {
        ["Authorization"] = "Basic " .. client_credentials
    }

    local status, res, err = zhttp:http_post_client(conf.keycloak_token_url,
            headers, encode_args(body, false, false), 1000)

    if err then
        return exit:internal_server_error(err)
    end

    if status == 400 then
        return exit(400, res)
    end

    local access_token = cjson_decode(res).access_token
    local refresh_token = cjson_decode(res).refresh_token


    -- 缓存
    -- tid - access_token - refresh_token

    -- 从access_token中解析出tid
    local jwt, err = jwt_decoder:new(access_token)
    if err then
        return exit:internal_server_error(err)
    end

    local tid = jwt.claims.jti

    return exit:send_redirect({}, { ["Location"] = state .. "?tid=" .. tid })
end

--
-- 处理来自各客户端获取令牌的请求
-- 使用tid换取token
--
local function hand_token_request(conf)
    local tid = kong.request.get_query_arg("tid")

    -- 根据tid获取access_token和refresh_token
    local access_token, refresh_token = get_token_by_tid(tid)

    local token = {
        access_token = re_signature(access_token),
        expire_in = 60,
        refresh_token = refresh_token
    }

    return exit:ok(cjson_encode(token), { ["Content-Type"] = "application/json; charset=utf-8" })
end

--
-- 处理来自各客户端刷新令牌的请求
-- 使用refresh_token刷新token
--
local function hand_refresh_request(conf)
    -- 请求中获取客户端凭证和refresh_token等参数

    local token = [[{"token":"jwt token","refresh_token":"jwt refresh token"}]]
    return exit:ok(token, { ["Content-Type"] = "application/json; charset=utf-8" })
end

--
-- 处理来自各客户端注销登录的请求
-- 清除令牌和用户的相关缓存
-- 请求认证中心注销会话
--
local function hand_logout_request(conf)
    local redirect_uri = kong.request.get_query_arg("redirect_uri")

    if nil == redirect_uri then
        return exit:unauthorized_error({ message = "No redirect_uri found", redirect_uri = "" })
    end

    local token = retrieve_token()

    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return exit:unauthorized_error({ message = "Unauthorized", redirect_uri = "" })
        elseif token_type == "table" then
            return exit:unauthorized_error({ message = "Multiple tokens provided", redirect_uri = "" })
        else
            return exit:unauthorized_error({ message = "Unrecognizable token", redirect_uri = "" })
        end
    end

    local jwt, kc_token = verify_token(token)

    if jwt.expired then
        return exit:unauthorized_error({ message = "Invalid token: token expired", redirect_uri = "" })
    end

    return exit:send_redirect({}, { ["Location"] = redirect_uri })
end

--
-- 校验权限
--
local function verify_authority(user_id, client_id, request_uri)

end

--
-- 处理非网关认证类的业务服务的请求
--
local function do_authentication(conf)

    -- 获取当前请求的来源
    -- 直接输入的地址请求，来源为空；页面点击的请求，来源为页面地址
    local referrer = kong.request.get_header("Referrer")

    local client_id = kong.request.get_header("X-Authenticated-Client-ID")
    --
    --if nil == client_id then
    --    return unauthorized_error({ message = "No client_id found", redirect_uri = "" })
    --end

    local token = retrieve_token()

    -- 如果token过期或者未携带，应该302到登录页
    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return redirect_to_auth(referrer, client_id, conf)
        elseif token_type == "table" then
            return exit:unauthorized_error({ message = "Multiple tokens provided", redirect_uri = "" })
        else
            return exit:unauthorized_error({ message = "Unrecognizable token", redirect_uri = "" })
        end
    end

    local jwt, kc_token = verify_token(token)
    if jwt.expired then
        return redirect_to_auth(referrer, client_id, conf)
    end

    local user_id = jwt.claims.sub
    local user_name = jwt.claims.preferred_username

    verify_authority(user_id, client_id, kong.request.get_path())

    -- 签名正确
    -- 请求头中设置一些用户信息
    kong.service.request.set_header("X-Authenticated-User-ID", user_id)
    kong.service.request.set_header("X-Authenticated-User-Name", user_name)

    -- 将Keycloak签发的令牌设置到请求头
    kong.service.request.set_header("Authorization", "Bearer " .. kc_token)

end

function _M.access(conf)
    -- 获取当前请求path
    local request_path = kong.request.get_path()

    -- 当前请求为认证重定向
    if nil ~= find(conf.kong_redirect_path, request_path) then
        return hand_redirect_request(conf)
    end

    -- 当前请求为签发令牌
    if nil ~= find(conf.kong_token_path, request_path) then
        return hand_token_request(conf)
    end

    -- 当前请求为刷新令牌，这里主动请求认证中心刷新后将令牌响应回客户端
    if nil ~= find(conf.kong_refresh_path, request_path) then
        return hand_refresh_request(conf)
    end

    -- 当前请求为注销会话，需要请求keycloak注销session，并销毁缓存中的token
    if nil ~= find(conf.kong_logout_path, request_path) then
        return hand_logout_request(conf)
    end

    -- 这里的请求需要校验携带的令牌，并判断时放过请求还是跳转至登录
    return do_authentication(conf)
end

return _M