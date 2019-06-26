--
-- 插件配置
-- User: zqzhou
-- Date: 2019/6/18
--
return {
    no_consumer = true,
    fields = {
        kong_host = { type = "string" },
        keycloak_token_url = { type = "string" },
        kong_redirect_path = { type = "string" },
        kong_token_path = { type = "string" },
        kong_refresh_path = {type = "string"},
        kong_logout_path = {type = "string"},
    },
    self_check = function(schema, plugin_t, dao, is_update)
        -- TODO: add check
        return true
    end
}