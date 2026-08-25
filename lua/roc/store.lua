local cjson = require("cjson.safe")
local policy = require("ro.policy")
local util = require("ro.util")
local log = require("ro.log")

local _M = { _VERSION = "1.0.0" }

local format = string.format
local concat = table.concat

local conf
local lock_dict
local cache
local cache_generation = -1

local EMPTY_STORE = {
    policies = {},
    profiles = {},
    identities = { allowAnonymous = false, tokens = {}, sources = {},
                   trustedHeaderSources = {} },
    settings = {
        ttlSeconds = 300,
        emergencyDeny = false,
        defaults = { maxStalenessSeconds = 900 },
        guard = { blocked = {}, allowExceptions = {} },
    },
    meta = { revision = 0, updatedAt = 0 },
}

local function store_path()
    return conf.dataDir .. "/store.json"
end

local function versions_dir()
    return conf.dataDir .. "/versions"
end

local function version_path(n)
    return format("%s/%d.json", versions_dir(), n)
end

local function current_path()
    return conf.dataDir .. "/current.json"
end

local function read_json(path)
    local fh = io.open(path, "r")
    if not fh then
        return nil, "not found"
    end
    local body = fh:read("*a")
    fh:close()
    local parsed, err = cjson.decode(body)
    if not parsed then
        return nil, "corrupt json in " .. path .. ": " .. tostring(err)
    end
    return parsed, nil, body
end

local function write_json_atomic(path, value)
    local body = cjson.encode(value)
    if not body then
        return nil, "cannot encode document"
    end
    local tmp = path .. ".tmp." .. tostring(ngx.worker.pid())
    local fh, ferr = io.open(tmp, "w")
    if not fh then
        return nil, "cannot open " .. tmp .. ": " .. tostring(ferr)
    end
    fh:write(body)
    fh:close()
    local ok, rerr = os.rename(tmp, path)
    if not ok then
        os.remove(tmp)
        return nil, "cannot rename into place: " .. tostring(rerr)
    end
    return true
end

local SAFE_DIR = "^/[A-Za-z0-9._/-]*$"

local function safe_data_dir(dir)
    if type(dir) ~= "string" or dir == "" or #dir > 4096 then
        return nil, "dataDir must be a non-empty absolute path"
    end
    if not dir:match(SAFE_DIR) then
        return nil, "dataDir may only contain A-Z a-z 0-9 . _ - / and must be absolute"
    end
    if dir:find("..", 1, true) then
        return nil, "dataDir must not contain a parent reference"
    end
    return dir
end

_M.safe_data_dir = safe_data_dir

function _M.init(c)
    conf = c
    local dir, derr = safe_data_dir(conf.dataDir)
    if not dir then
        return nil, derr
    end
    lock_dict = ngx.shared.roc_lock
    if not lock_dict then
        return nil, "the roc_lock shared dictionary is not configured, so "
            .. "concurrent writes to the policy store cannot be serialised"
    end
    os.execute("mkdir -p " .. dir .. "/versions 2>/dev/null")
    local existing = read_json(store_path())
    if not existing then
        local seed = util.deep_copy(EMPTY_STORE)
        seed.meta.updatedAt = util.now()
        local ok, err = write_json_atomic(store_path(), seed)
        if not ok then
            return nil, err
        end
    end
    return true
end

local function lock(timeout)
    if not lock_dict then
        return nil, "the store lock is unavailable"
    end
    local deadline = util.now() + (timeout or 5)
    while util.now() < deadline do
        local ok = lock_dict:add("write", 1, 10)
        if ok then
            return true
        end
        ngx.sleep(0.01)
    end
    return nil, "timed out waiting for the store lock"
end

local function unlock()
    if lock_dict then
        lock_dict:delete("write")
    end
end

function _M.load()
    local generation = lock_dict and (lock_dict:get("generation") or 0) or 0
    if cache and cache_generation == generation then
        return cache
    end
    local data, err = read_json(store_path())
    if not data then
        return nil, err
    end
    data.policies = data.policies or {}
    data.profiles = data.profiles or {}
    data.identities = data.identities or util.deep_copy(EMPTY_STORE.identities)
    data.settings = data.settings or util.deep_copy(EMPTY_STORE.settings)
    data.meta = data.meta or { revision = 0 }
    cache = data
    cache_generation = generation
    return data
end

local function save(data)
    data.meta = data.meta or {}
    data.meta.revision = (data.meta.revision or 0) + 1
    data.meta.updatedAt = util.now()
    local ok, err = write_json_atomic(store_path(), data)
    cache = nil
    cache_generation = -1
    if not ok then
        return nil, err
    end
    if lock_dict then
        lock_dict:incr("generation", 1, 0)
    end
    return data.meta.revision
end

function _M.mutate(fn)
    local ok, lerr = lock()
    if not ok then
        return nil, lerr
    end
    local result, err
    local pok, perr = pcall(function()
        local shared, derr = _M.load()
        if not shared then
            err = derr
            return
        end
        local data = util.deep_copy(shared)
        local mutated, merr = fn(data)
        if not mutated then
            err = merr
            return
        end
        local revision, serr = save(data)
        if not revision then
            err = serr
            return
        end
        result = revision
    end)
    cache = nil
    cache_generation = -1
    unlock()
    if not pok then
        return nil, tostring(perr)
    end
    if err then
        return nil, err
    end
    return result
end

local VALID_NAME = "^[a-z0-9][a-z0-9%.%-_]*$"

function _M.valid_name(name)
    return type(name) == "string" and #name > 0 and #name <= 128
        and name:match(VALID_NAME) ~= nil
end

function _M.normalize_policy(doc, fallback_name)
    if type(doc) ~= "table" then
        return nil, "policy document must be an object"
    end
    local kind = doc.kind
    if kind ~= nil and kind ~= "EgressPolicy" then
        return nil, "unsupported kind: " .. tostring(kind)
    end
    local meta = doc.metadata or {}
    local spec = doc.spec or doc
    local name = meta.name or doc.name or fallback_name
    if not _M.valid_name(name) then
        return nil, "invalid policy name"
    end
    local out = {
        name = name,
        tier = meta.tier or spec.tier or doc.tier or "profile",
        priority = tonumber(meta.priority or spec.priority or doc.priority) or 0,
        defaultAction = spec.defaultAction or "deny",
        selector = spec.selector,
        rules = spec.rules or {},
        description = meta.description or spec.description,
    }
    return out
end

function _M.normalize_profile(doc, fallback_name)
    if type(doc) ~= "table" then
        return nil, "profile document must be an object"
    end
    local kind = doc.kind
    if kind ~= nil and kind ~= "SandboxProfile" then
        return nil, "unsupported kind: " .. tostring(kind)
    end
    local meta = doc.metadata or {}
    local spec = doc.spec or doc
    local name = meta.name or doc.name or fallback_name
    if not _M.valid_name(name) then
        return nil, "invalid profile name"
    end
    local egress = spec.egress or {}
    if egress.default ~= nil and egress.default ~= "deny" then
        return nil, "sandbox profiles must keep default: deny"
    end
    local rules = {}
    for i, entry in ipairs(egress.allow or {}) do
        if type(entry) ~= "table" then
            return nil, "egress.allow[" .. i .. "] must be an object"
        end
        local dest = {}
        if entry.host then
            dest.hostnames = { entry.host }
        end
        if entry.hosts then
            dest.hostnames = entry.hosts
        end
        if entry.domain then
            dest.hostnameSuffixes = { entry.domain }
        end
        if entry.domains then
            dest.hostnameSuffixes = entry.domains
        end
        if entry.cidr then
            dest.cidrs = { entry.cidr }
        end
        if entry.cidrs then
            dest.cidrs = entry.cidrs
        end
        local ports = entry.ports
        if not ports and entry.port then
            ports = { entry.port }
        end
        local protocols = entry.protocols
        if not protocols and entry.protocol then
            protocols = { entry.protocol }
        end
        rules[#rules + 1] = {
            name = entry.name or (name .. "-allow-" .. i),
            action = "allow",
            destinations = dest,
            ports = ports,
            protocols = protocols,
            methods = entry.methods,
            paths = entry.paths,
            rateLimit = entry.rateLimit,
            connections = entry.connections,
            bandwidth = entry.bandwidth,
            tls = entry.tls,
        }
    end
    for i, entry in ipairs(egress.deny or {}) do
        local dest = {}
        if entry.host then dest.hostnames = { entry.host } end
        if entry.hosts then dest.hostnames = entry.hosts end
        if entry.domain then dest.hostnameSuffixes = { entry.domain } end
        if entry.domains then dest.hostnameSuffixes = entry.domains end
        if entry.cidr then dest.cidrs = { entry.cidr } end
        if entry.cidrs then dest.cidrs = entry.cidrs end
        rules[#rules + 1] = {
            name = entry.name or (name .. "-deny-" .. i),
            action = "deny",
            destinations = dest,
            ports = entry.ports,
            protocols = entry.protocols,
        }
    end
    return {
        name = "profile/" .. name,
        tier = "profile",
        priority = tonumber(spec.priority) or 10,
        defaultAction = "deny",
        selector = { profiles = { name } },
        rules = rules,
        description = spec.description or ("Generated from SandboxProfile " .. name),
    }, name
end

function _M.compile_bundle(data, version)
    local policies = {}
    local names = util.sorted_keys(data.policies or {})
    for _, name in ipairs(names) do
        local normalized, err = _M.normalize_policy(data.policies[name], name)
        if not normalized then
            return nil, "policy " .. name .. ": " .. tostring(err)
        end
        policies[#policies + 1] = normalized
    end
    local profile_names = util.sorted_keys(data.profiles or {})
    for _, name in ipairs(profile_names) do
        local normalized, err = _M.normalize_profile(data.profiles[name], name)
        if not normalized then
            return nil, "profile " .. name .. ": " .. tostring(err)
        end
        policies[#policies + 1] = normalized
    end

    local settings = data.settings or {}
    local array_mt = cjson.empty_array_mt
    local function as_array(t)
        if type(t) ~= "table" then
            return setmetatable({}, array_mt)
        end
        if next(t) == nil then
            return setmetatable({}, array_mt)
        end
        return t
    end

    local guard = util.deep_copy(settings.guard or {})
    guard.blocked = as_array(guard.blocked)
    guard.allowExceptions = as_array(guard.allowExceptions)

    local identities = util.deep_copy(data.identities or {})
    identities.tokens = identities.tokens or {}
    identities.sources = as_array(identities.sources)
    identities.trustedHeaderSources = as_array(identities.trustedHeaderSources)

    local bundle = {
        version = version,
        issuedAt = util.now(),
        ttlSeconds = settings.ttlSeconds or 300,
        emergencyDeny = settings.emergencyDeny == true,
        defaults = settings.defaults or {},
        guard = guard,
        identities = identities,
        policies = as_array(policies),
    }
    return bundle
end

function _M.validate_bundle(bundle)
    local compiled, err = policy.compile(bundle)
    if not compiled then
        return nil, err
    end
    return compiled
end

function _M.current_version()
    local cur = read_json(current_path())
    if not cur then
        return 0
    end
    return tonumber(cur.version) or 0
end

function _M.active_bundle()
    local version = _M.current_version()
    if version == 0 then
        return nil, "no bundle has been published yet"
    end
    local bundle, err = read_json(version_path(version))
    if not bundle then
        return nil, err
    end
    return bundle
end

function _M.list_versions()
    local index = read_json(versions_dir() .. "/index.json") or { versions = {} }
    return index.versions or {}
end

function _M.highest_version()
    local index = read_json(versions_dir() .. "/index.json") or {}
    local highest = tonumber(index.highWater) or 0
    for _, entry in ipairs(index.versions or {}) do
        local n = tonumber(entry.version) or 0
        if n > highest then highest = n end
    end
    local active = _M.current_version()
    if active > highest then highest = active end
    return highest
end

function _M.get_version(n)
    return read_json(version_path(n))
end

function _M.publish(actor, note)
    local ok, lerr = lock(10)
    if not ok then
        return nil, lerr
    end
    local result, err
    local pok, perr = pcall(function()
        local data, derr = _M.load()
        if not data then
            err = derr
            return
        end
        local next_version = _M.highest_version() + 1
        local bundle, berr = _M.compile_bundle(data, next_version)
        if not bundle then
            err = berr
            return
        end
        local compiled, verr = _M.validate_bundle(bundle)
        if not compiled then
            err = verr
            return
        end
        if read_json(version_path(next_version)) then
            err = format("version %d already exists; refusing to overwrite an "
                .. "immutable bundle", next_version)
            return
        end
        local wok, werr = write_json_atomic(version_path(next_version), bundle)
        if not wok then
            err = werr
            return
        end
        local index = read_json(versions_dir() .. "/index.json") or { versions = {} }
        index.versions = index.versions or {}
        index.versions[#index.versions + 1] = {
            version = next_version,
            publishedAt = util.now(),
            actor = actor or "unknown",
            note = note,
            revision = data.meta and data.meta.revision or 0,
            policyCount = #bundle.policies,
            ruleCount = compiled.rule_count,
            digest = util.content_digest(bundle),
        }
        if #index.versions > 200 then
            table.remove(index.versions, 1)
        end
        index.highWater = next_version
        write_json_atomic(versions_dir() .. "/index.json", index)
        local cok, cerr = write_json_atomic(current_path(), {
            version = next_version, activatedAt = util.now(), actor = actor,
        })
        if not cok then
            err = cerr
            return
        end
        result = { version = next_version, summary = compiled:summary() }
    end)
    unlock()
    if not pok then
        return nil, tostring(perr)
    end
    if err then
        return nil, err
    end
    return result
end

function _M.rollback(version, actor)
    local bundle, err = read_json(version_path(version))
    if not bundle then
        return nil, "version " .. tostring(version) .. " is not available"
    end
    local compiled, verr = _M.validate_bundle(bundle)
    if not compiled then
        return nil, "stored version no longer validates: " .. tostring(verr)
    end
    local ok, lerr = lock(10)
    if not ok then
        return nil, lerr
    end
    local cok, cerr = write_json_atomic(current_path(), {
        version = version, activatedAt = util.now(), actor = actor,
        rolledBack = true,
    })
    unlock()
    if not cok then
        return nil, cerr
    end
    return { version = version, summary = compiled:summary() }
end

return _M
