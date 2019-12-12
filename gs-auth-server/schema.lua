local typedefs = require "kong.db.schema.typedefs"

return {
    name = "gs-auth-server",
    fields = {
        { run_on = typedefs.run_on_first },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                { gsauth_host = typedefs.host({ required = true }), },
                { gsauth_port = typedefs.port({ required = true }), },
                { gsauth_proxy_path = { type = "string", required = true, default = "/gsauth", }, },
                { gsauth_logout_path = { type = "string", required = true, default = "/v3/logout" }, },
                { gsauth_check_token_path = { type = "string", required = true, default = "/v3/oauth/check-token" }, },
                { gsauth_privileges_path = { type = "string", required = true, default = "/v3/clients/{gsauth_client_id}/user/privileges" }, },

                --{ service_token_heartbeat = { type = "string", required = false, default = "/token/heartbeat", }, },

                { policy = { type = "string", default = "redis", one_of = { "cluster", "redis" }, }, },

                { redis_host = typedefs.host },
                { redis_port = typedefs.port({ default = 6379 }), },
                { redis_password = { type = "string", len_min = 0 }, },
                { redis_timeout = { type = "number", default = 2000 }, },
                { redis_database = { type = "number", default = 0 }, },
            },
        },
        },
    },
}

