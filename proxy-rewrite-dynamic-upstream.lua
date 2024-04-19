-- author: zhangshumin
-- date: 2024-04-11
-- description:
--      rewrite host to dynamic path, such as: abc.com/(1.1.1.1)/(2.2.2.2)/(80)/(test) --> $2:$3/$4
-- route config such as:
-- "plugins": {
--     "proxy-rewrite-dynamic": {
--       "regex_host": [
--         "^/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)/(.+)",
--         "$1"
--       ],
--       "regex_port": [
--         "^/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)/(.+)",
--         "$3"
--       ],
--       "regex_uri": [
--         "^/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)/(.+)",
--         "$4"
--       ]
--     }
--   },
local ngx = ngx
local core = require("apisix.core")
local plugin = require("apisix.plugin")
local upstream = require("apisix.upstream")

local re_sub      = ngx.re.sub
local re_match    = ngx.re.match
local req_set_uri = ngx.req.set_uri
local sub_str     = string.sub
local str_find    = core.string.find
local plugin_name = "proxy-rewrite-dynamic-upstream"
local tonumber = tonumber

local schema = {
    type = "object",
    properties = {
        uri = {
            description = "new uri for upstream",
            type        = "string",
            minLength   = 1,
            maxLength   = 4096,
            pattern     = [[^\/.*]],
        },
        regex_uri = {
            description = "new uri that substitute from client uri " ..
                          "for upstream, lower priority than uri property",
            type        = "array",
            minItems    = 2,
            items       = {
                description = "regex uri",
                type = "string",
            }
        },
        host = {
            description = "new host for upstream",
            type        = "string",
            pattern     = [[^[0-9a-zA-Z-.]+(:\d{1,5})?$]],
        },
        regex_host = {
            description = "new host that substitute from client uri " ..
                          "for upstream, lower priority than uri property",
            type        = "array",
            minItems    = 2,
            items       = {
                description = "regex host",
                type = "string",
            }
        },
        port = {
            description = "new port for upstream",
            type        = "string",
            pattern     = [[^[1-9].[0-9]{0,4}$]],
        },
        regex_port = {
            description = "new port that substitute from client uri " ..
                          "for upstream, lower priority than uri property",
            type        = "array",
            minItems    = 2,
            items       = {
                description = "regex port",
                type = "string",
            }
        },
    },
    minProperties = 1,
}

local _M = {
    version = 0.1,
    priority = 98,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function escape_separator(s)
    return re_sub(s, [[\?]], "%3F", "jo")
end

function _M.access(conf, ctx)
    -- Get the request
    local request_uri = ngx.var.uri
    local request_host = ngx.var.host
    local request_port = ngx.var.port
    local request_scheme = ngx.var.scheme
    local args = ngx.var.args
    local separator_escaped = false

    -- init upstream
    local upstream_host
    local upstream_port
    local upstream_uri
    local upstream_scheme

    if conf.scheme ~= nil then
        upstream_scheme = conf.scheme
    end

    if conf.uri ~= nil then
        separator_escaped = true
        upstream_uri = core.utils.resolve_var(conf.uri, ctx.var, escape_separator)

    elseif conf.regex_uri ~= nil then
        if not str_find(request_uri, "?") then
            separator_escaped = true
        end

        local error_msg
        for i = 1, #conf.regex_uri, 2 do
            local captures, err = re_match(request_uri, conf.regex_uri[i], "jo")
            if err then
                error_msg = "failed to match the uri " .. ctx.var.uri ..
                    " (" .. conf.regex_uri[i] .. ") " .. " : " .. err
                break
            end

            if captures then
                ctx.proxy_rewrite_regex_uri_captures = captures

                local uri, _, err = re_sub(request_uri,
                    conf.regex_uri[i], conf.regex_uri[i + 1], "jo")
                if uri then
                    upstream_uri = uri
                else
                    error_msg = "failed to substitute the uri " .. ngx.var.uri ..
                        " (" .. conf.regex_uri[i] .. ") with " ..
                        conf.regex_uri[i + 1] .. " : " .. err
                end

                break
            end
        end

        if error_msg ~= nil then
            core.log.error(error_msg)
            return 500, { error_msg = error_msg }
        end
    end

    if conf.host ~= nil then
        upstream_host = conf.host
    
    elseif conf.regex_host ~= nil then
        local error_msg
        -- core.log.warn("uri: ", upstream_uri)
        -- core.log.warn("ngx uri: ", ngx.var.uri)
        -- local m, err = re_match(upstream_uri, conf.regex_host[1], "jo")
        -- core.log.warn("m: ", m, conf.regex_host[1])
        local host, _, err = re_sub(request_uri, conf.regex_host[1], conf.regex_host[2], "jo")
	    -- core.log.warn("host: ", host, conf.regex_host[1], conf.regex_host[2])
        if host then
            upstream_host = host
        else
            error_msg = "failed to substitute the host " .. ngx.var.uri ..
                " (" .. conf.regex_host[1] .. ") with " ..
                conf.regex_host[2] .. " : " .. err
        end
        
        if error_msg ~= nil then
            core.log.error(error_msg)
            return 500, { error_msg = error_msg }
        end
    end

    if conf.port ~= nil then
        upstream_port = conf.port
    
    elseif conf.regex_port ~= nil then
        local error_msg

        local port, _, err = re_sub(request_uri, conf.regex_port[1], conf.regex_port[2], "jo")
	    -- core.log.warn("regex port: ", port, conf.regex_port[1], conf.regex_port[2])
        if port then
            upstream_port = port
        else
            error_msg = "failed to substitute the port " .. ngx.var.uri ..
                " (" .. conf.regex_port[1] .. ") with " ..
                conf.regex_port[2] .. " : " .. err
        end
        
        if error_msg ~= nil then
            core.log.error(error_msg)
            return 500, { error_msg = error_msg }
        end
    end

    upstream_port = tonumber(upstream_port)

    -- core.log.warn("host: ", upstream_host)
    -- core.log.warn("port: ", upstream_port)
    -- core.log.warn("uri: ", upstream_uri)
    -- core.log.warn("scheme: ", upstream_scheme)

    -- set path
    ngx.req.set_uri("/" .. upstream_uri)

    -- set upstream
    -- some params can be set from existing upstream config
    -- or can be set by plugin conf
    local up_conf = {
        timeout = {
            connect = 60,
            send = 60,
            read = 60
        },
        scheme = upstream_scheme,
        type = "roundrobin",
        pass_host = "pass",
        keepalive_pool = {
            idle_timeout = 60,
            requests = 1000,
            size = 320
        },
        hash_on = "vars",
        nodes = {
            {
                priority = 0,
                port = upstream_port,
                host = upstream_host,
                weight = 1
            }
        }
    }

    local ok, err = upstream.check_schema(up_conf)
    if not ok then
        core.log.error("failed to validate generated upstream: ", err)
        return 500, err
    end

    local matched_route = ctx.matched_route
    up_conf.parent = matched_route
    local upstream_key = up_conf.type .. "#route_" .. matched_route.value.id
    core.log.info("upstream_key: ", upstream_key)

    upstream.set(ctx, upstream_key, ctx.conf_version, up_conf)
end

return _M
