return {
    --支持数据库postgres和cassandra
    --当前数据库使用postgres，未定义cassandra创建方式
    postgres = {
        up = [[
            CREATE TABLE IF NOT EXISTS "gauth_tokens" (
                "id"                    UUID                         PRIMARY KEY,
                "access_token_client_id" TEXT                        UNIQUE,
                "access_token"          TEXT,
                "client_id"             TEXT,
                "expires_in"            BIGINT,
                "permissions"           TEXT,
                "created_at"            TIMESTAMP WITHOUT TIME ZONE  DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
                "ttl"                   timestamptz(6)
            );

            CREATE TABLE IF NOT EXISTS "gauth_token_clients" (
                "id"                    UUID                        PRIMARY KEY,
                "access_token"          TEXT                        UNIQUE,
                "client_ids"            TEXT,
                "created_at"            TIMESTAMP WITHOUT TIME ZONE  DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
                "ttl"                   timestamptz(6)
            );
        ]]
    },
    cassandra = {
        up = [[

        ]]
    },
}
