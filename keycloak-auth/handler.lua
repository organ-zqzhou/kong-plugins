--
-- 插件功能实现
-- User: zqzhou
-- Date: 2019/6/18
--
local BasePlugin = require "kong.plugins.base_plugin"

local authn = require "kong.plugins.keycloak-auth.auth.authn"
local authz = require "kong.plugins.keycloak-auth.auth.authz"

local KeycloakAuthHandler = BasePlugin:extend()

KeycloakAuthHandler.PRIORITY = 1998
KeycloakAuthHandler.VERSION = "1.0.0"



function KeycloakAuthHandler:access(conf)
    authn.access(conf)
    authz.access(conf)
end

function KeycloakAuthHandler:new()
    KeycloakAuthHandler.super.new(self, "keycloak-auth")
end

return KeycloakAuthHandler
