local _M = { _VERSION = "1.0.0" }

local sub = string.sub
local find = string.find
local byte = string.byte
local gsub = string.gsub
local lower = string.lower
local concat = table.concat

local MAX_DEPTH = 32
local MAX_LINES = 20000

local function strip_comment(line)
    local in_single, in_double = false, false
    for i = 1, #line do
        local c = sub(line, i, i)
        if c == "'" and not in_double then
            in_single = not in_single
        elseif c == '"' and not in_single then
            in_double = not in_double
        elseif c == "#" and not in_single and not in_double then
            if i == 1 or find(sub(line, i - 1, i - 1), "[ \t]") then
                return sub(line, 1, i - 1)
            end
        end
    end
    return line
end

local function rtrim(s)
    return (gsub(s, "%s+$", ""))
end

local function unquote(s)
    local first = sub(s, 1, 1)
    local last = sub(s, -1)
    if #s >= 2 and first == '"' and last == '"' then
        local body = sub(s, 2, -2)
        body = gsub(body, "\\(.)", function(c)
            if c == "n" then return "\n" end
            if c == "t" then return "\t" end
            if c == "r" then return "\r" end
            if c == "0" then return "\0" end
            return c
        end)
        return body, true
    end
    if #s >= 2 and first == "'" and last == "'" then
        return gsub(sub(s, 2, -2), "''", "'"), true
    end
    return s, false
end

local parse_flow

local function parse_scalar(raw)
    local s = rtrim(raw)
    if s == "" then
        return nil
    end
    local first = sub(s, 1, 1)
    if first == "[" or first == "{" then
        return parse_flow(s)
    end
    local text, quoted = unquote(s)
    if quoted then
        return text
    end
    local l = lower(text)
    if l == "null" or l == "~" then
        return nil
    end
    if l == "true" or l == "yes" or l == "on" then
        return true
    end
    if l == "false" or l == "no" or l == "off" then
        return false
    end
    local n = tonumber(text)
    if n ~= nil and find(text, "^[%-+]?[%d%.eExXa-fA-F+]+$") then
        return n
    end
    return text
end

local function split_flow_items(body)
    local items, n = {}, 0
    local depth = 0
    local in_single, in_double = false, false
    local start = 1
    for i = 1, #body do
        local c = sub(body, i, i)
        if c == "'" and not in_double then
            in_single = not in_single
        elseif c == '"' and not in_single then
            in_double = not in_double
        elseif not in_single and not in_double then
            if c == "[" or c == "{" then
                depth = depth + 1
            elseif c == "]" or c == "}" then
                depth = depth - 1
            elseif c == "," and depth == 0 then
                n = n + 1
                items[n] = sub(body, start, i - 1)
                start = i + 1
            end
        end
    end
    local tail = sub(body, start)
    if rtrim(tail) ~= "" or n > 0 then
        n = n + 1
        items[n] = tail
    end
    return items, n
end

local flow_depth = 0
local parse_flow_inner

parse_flow = function(s)
    if flow_depth >= MAX_DEPTH then
        return nil, "flow collection nested too deeply"
    end
    flow_depth = flow_depth + 1
    local value, err = parse_flow_inner(s)
    flow_depth = flow_depth - 1
    return value, err
end

parse_flow_inner = function(s)
    s = rtrim(s)
    local first = sub(s, 1, 1)
    if first == "[" then
        if sub(s, -1) ~= "]" then
            return nil, "unterminated flow sequence"
        end
        local body = sub(s, 2, -2)
        local out, n = {}, 0
        if rtrim(body) == "" then
            return out
        end
        local items, count = split_flow_items(body)
        for i = 1, count do
            local item = items[i]:gsub("^%s+", "")
            local value, err = parse_scalar(item)
            if err then
                return nil, err
            end
            n = n + 1
            out[n] = value
        end
        return out
    end
    if first == "{" then
        if sub(s, -1) ~= "}" then
            return nil, "unterminated flow mapping"
        end
        local body = sub(s, 2, -2)
        local out = {}
        if rtrim(body) == "" then
            return out
        end
        local items, count = split_flow_items(body)
        for i = 1, count do
            local item = items[i]:gsub("^%s+", "")
            local colon = find(item, ":", 1, true)
            if not colon then
                return nil, "flow mapping entry without a colon"
            end
            local key = rtrim(sub(item, 1, colon - 1))
            local raw = sub(item, colon + 1):gsub("^%s+", "")
            local value, verr = parse_scalar(raw)
            if verr then
                return nil, verr
            end
            out[(unquote(key))] = value
        end
        return out
    end
    return nil, "not a flow collection"
end

local function tokenize(text)
    local lines, n = {}, 0
    local pos = 1
    local len = #text
    local lineno = 0
    while pos <= len + 1 do
        local nl = find(text, "\n", pos, true) or (len + 1)
        local raw = sub(text, pos, nl - 1)
        lineno = lineno + 1
        if lineno > MAX_LINES then
            return nil, "document has too many lines"
        end
        raw = gsub(raw, "\r$", "")
        local content = rtrim(strip_comment(raw))
        if content ~= "" then
            local indent = 0
            local i = 1
            while i <= #content do
                local c = byte(content, i)
                if c == 32 then
                    indent = indent + 1
                    i = i + 1
                elseif c == 9 then
                    return nil, "tabs are not permitted for indentation (line "
                        .. lineno .. ")"
                else
                    break
                end
            end
            n = n + 1
            lines[n] = {
                indent = indent,
                text = sub(content, i),
                lineno = lineno,
            }
        end
        pos = nl + 1
    end
    return lines, n
end

local function split_key(text)
    local in_single, in_double = false, false
    for i = 1, #text do
        local c = sub(text, i, i)
        if c == "'" and not in_double then
            in_single = not in_single
        elseif c == '"' and not in_single then
            in_double = not in_double
        elseif c == ":" and not in_single and not in_double then
            local after = sub(text, i + 1, i + 1)
            if after == "" or after == " " then
                return sub(text, 1, i - 1), sub(text, i + 2)
            end
        end
    end
    return nil
end

local parse_block

local function parse_value_at(lines, index, count, indent, depth)
    if depth > MAX_DEPTH then
        return nil, index, "document nesting is too deep"
    end
    if index > count or lines[index].indent < indent then
        return nil, index
    end
    return parse_block(lines, index, count, lines[index].indent, depth)
end

parse_block = function(lines, index, count, indent, depth)
    if depth > MAX_DEPTH then
        return nil, index, "document nesting is too deep"
    end
    local first = lines[index]
    if not first then
        return nil, index
    end

    if sub(first.text, 1, 2) == "- " or first.text == "-" then
        local seq, n = {}, 0
        while index <= count do
            local line = lines[index]
            if line.indent < indent then
                break
            end
            if line.indent > indent then
                return nil, index, "unexpected indentation at line " .. line.lineno
            end
            if sub(line.text, 1, 2) ~= "- " and line.text ~= "-" then
                break
            end
            local rest = line.text == "-" and "" or sub(line.text, 3)
            index = index + 1
            if rest == "" then
                local value, next_index, err = parse_value_at(lines, index, count,
                    indent + 1, depth + 1)
                if err then return nil, next_index, err end
                n = n + 1
                seq[n] = value
                index = next_index
            else
                local key, inline = split_key(rest)
                if key then
                    local map = {}
                    local item_indent = indent + 2
                    local first_key = unquote(rtrim(key))
                    if inline == "" then
                        local value, next_index, err = parse_value_at(lines, index,
                            count, item_indent, depth + 1)
                        if err then return nil, next_index, err end
                        map[first_key] = value
                        index = next_index
                    else
                        local value, serr = parse_scalar(inline)
                        if serr then return nil, index, serr end
                        map[first_key] = value
                    end
                    while index <= count and lines[index].indent >= item_indent do
                        local sub_line = lines[index]
                        local skey, sinline = split_key(sub_line.text)
                        if not skey then
                            return nil, index, "expected a mapping key at line "
                                .. sub_line.lineno
                        end
                        index = index + 1
                        local clean_skey = unquote(rtrim(skey))
                        if map[clean_skey] ~= nil then
                            return nil, index, "duplicate mapping key '"
                                .. tostring(clean_skey) .. "' at line "
                                .. sub_line.lineno
                                .. "; the later value would silently override "
                                .. "the earlier one"
                        end
                        if rtrim(sinline) == "" then
                            local value, next_index, err = parse_value_at(lines,
                                index, count, sub_line.indent + 1, depth + 1)
                            if err then return nil, next_index, err end
                            map[clean_skey] = value
                            index = next_index
                        else
                            local value, serr = parse_scalar(sinline)
                            if serr then return nil, index, serr end
                            map[clean_skey] = value
                        end
                    end
                    n = n + 1
                    seq[n] = map
                else
                    local value, serr = parse_scalar(rest)
                    if serr then return nil, index, serr end
                    n = n + 1
                    seq[n] = value
                end
            end
        end
        return seq, index
    end

    local map = {}
    local seen = false
    while index <= count do
        local line = lines[index]
        if line.indent < indent then
            break
        end
        if line.indent > indent then
            return nil, index, "unexpected indentation at line " .. line.lineno
        end
        if sub(line.text, 1, 2) == "- " then
            break
        end
        local key, inline = split_key(line.text)
        if not key then
            if not seen then
                return parse_scalar(line.text), index + 1
            end
            return nil, index, "expected a mapping key at line " .. line.lineno
        end
        seen = true
        index = index + 1
        local clean_key = unquote(rtrim(key))
        if map[clean_key] ~= nil then
            return nil, index, "duplicate mapping key '" .. tostring(clean_key)
                .. "' at line " .. line.lineno
                .. "; the later value would silently override the earlier one"
        end
        if rtrim(inline) == "" then
            local value, next_index, err = parse_value_at(lines, index, count,
                indent + 1, depth + 1)
            if err then return nil, next_index, err end
            map[clean_key] = value
            index = next_index
        else
            local value, err = parse_scalar(inline)
            if err then
                return nil, index, err
            end
            map[clean_key] = value
        end
    end
    return map, index
end

function _M.parse(text)
    flow_depth = 0
    if type(text) ~= "string" then
        return nil, "yaml input must be a string"
    end
    if #text > 4194304 then
        return nil, "yaml document is too large"
    end
    local lines, count = tokenize(text)
    if not lines then
        return nil, count
    end
    if count == 0 then
        return {}
    end
    local start = 1
    if lines[1].text == "---" then
        start = 2
    end
    if start > count then
        return {}
    end
    local value, index, err = parse_block(lines, start, count, lines[start].indent, 1)
    if err then
        return nil, err
    end
    if index <= count and lines[index].text ~= "..." then
        return nil, "unexpected content at line " .. lines[index].lineno
    end
    return value
end

function _M.looks_like_yaml(text)
    if type(text) ~= "string" then
        return false
    end
    local trimmed = text:gsub("^%s+", "")
    local first = sub(trimmed, 1, 1)
    return first ~= "{" and first ~= "["
end

return _M
