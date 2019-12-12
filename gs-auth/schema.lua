local typedefs = require "kong.db.schema.typedefs"

local gsauth_whitelist = {
    "/v3/oauth/check-token",
    "/v3/oauth/authorize",
    "/v3/oauth/token",
    "/v3/logout"
}

return {
    name = "gs-auth",
    fields = {
        { run_on = typedefs.run_on_first },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                { gsauth_host = typedefs.host({ required = true }), },
                { gsauth_port = typedefs.port({ required = true }), },
                { gsauth_client_id = { type = "string", required = true }, },
                { gsauth_check_token_path = { type = "string", required = true, default = "/v3/oauth/check-token" }, },
                { gsauth_privileges_path = { type = "string", required = true, default = "/v3/clients/{gsauth_client_id}/user/privileges" }, },

                --{ service_privileges_flush = { type = "string", required = false, default = "/privileges/flush", }, },
                --{ service_token_invalidate = { type = "string", required = false, default = "/token/invalidate", }, },
                --{ service_token_heartbeat = { type = "string", required = false, default = "/token/heartbeat", }, },

                { policy = { type = "string", default = "redis", one_of = { "cluster", "redis" }, }, },

                { redis_host = typedefs.host },
                { redis_port = typedefs.port({ default = 6379 }), },
                { redis_password = { type = "string", len_min = 0 }, },
                { redis_timeout = { type = "number", default = 2000 }, },
                { redis_database = { type = "number", default = 0 }, },

                { authn_whitelist = { type = "array", elements = { type = "string" }, }, },
                { authz_whitelist = { type = "array", elements = { type = "string" }, }, },
            },
        },
        },
    },
}

