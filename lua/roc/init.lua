local cjson = require("cjson.safe")
local store = require("roc.store")
local api = require("roc.api")
local metrics = require("ro.metrics")
local log = require("ro.log")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local conf

local DEFAULTS = {
    dataDir = "/var/lib/rokh-oghab",
    allowFrom = {},
    principals = {},
    audit = {
        path = "/dev/stdout",
        level = "info",
        capacity = 2048,
        bufferMax = 1,
        flushInterval = 0.2,
    },
}

function _M.config()
    return conf
end

local function merge(base, override)
    if type(override) ~= "table" then
        return base
    end
    for k, v in pairs(override) do
        if type(v) == "table" and type(base[k]) == "table"
            and not util.is_array(v) then
            merge(base[k], v)
        else
            base[k] = v
        end
    end
    return base
end

function _M.init()
    conf = util.deep_copy(DEFAULTS)
    local path = os.getenv("RO_CONTROLLER_CONFIG")
        or "/etc/rokh-oghab/controller.json"
    local fh = io.open(path, "r")
    if fh then
        local body = fh:read("*a")
        fh:close()
        local parsed, err = cjson.decode(body)
        if not parsed then
            ngx.log(ngx.ERR, "ro-controller: cannot parse ", path, ": ",
                tostring(err))
        else
            merge(conf, parsed)
        end
    end

    local data_dir = os.getenv("RO_CONTROLLER_DATA_DIR")
    if data_dir and data_dir ~= "" then
        conf.dataDir = data_dir
    end

    local function add_principal(env_name, name, role)
        local value = os.getenv(env_name)
        if value and value ~= "" then
            conf.principals[#conf.principals + 1] = {
                name = name, role = role, token = value,
            }
        end
    end
    add_principal("RO_CONTROLLER_ADMIN_TOKEN", "bootstrap-admin", "admin")
    add_principal("RO_CONTROLLER_OPERATOR_TOKEN", "bootstrap-operator", "operator")
    add_principal("RO_CONTROLLER_READER_TOKEN", "bootstrap-reader", "reader")
    add_principal("RO_CONTROLLER_GATEWAY_TOKEN", "bootstrap-gateway", "gateway")

    metrics.init("ro_metrics", { max_series = 5000 })
    metrics.define("roc_requests_total", "counter",
        "Control-plane API requests received.")
    metrics.define("roc_api_errors_total", "counter",
        "Control-plane API requests rejected.")
    metrics.define("roc_publish_total", "counter",
        "Policy bundle publish attempts.")
    metrics.define("roc_active_version", "gauge",
        "Currently active policy bundle version.")
    metrics.define("roc_bundle_served_total", "counter",
        "Policy bundles served to gateways.")

    log.init({
        path = conf.audit.path,
        level = conf.audit.level,
        capacity = conf.audit.capacity,
        buffer_max = conf.audit.bufferMax,
        flush_interval = conf.audit.flushInterval,
        dict = "ro_audit",
        component = "ro-controller",
        log_paths = true,
    })

    local ok, err = store.init(conf)
    if not ok then
        ngx.log(ngx.ERR, "ro-controller: cannot initialise store: ", tostring(err))
        return
    end
    api.configure(conf)

    if #conf.principals == 0 then
        ngx.log(ngx.WARN, "ro-controller: no principals configured; "
            .. "every authenticated endpoint will refuse access")
    end
    metrics.set("roc_active_version", nil, store.current_version())
end

function _M.init_worker()
    log.start()
end

return _M
