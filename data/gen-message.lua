local what = arg[1]
local prefix = arg[2]
local type = prefix == 'ctl' and 'ctl' or 'svc'
local data = dofile(arg[3])

local p = {indent=0}
function p:print(fmt, ...)
	if fmt then
		io.write(string.rep('\t', self.indent))
		io.write(string.format(fmt, ...))
	end
	if self.endline then
		io.write(self.endline)
	end
end

local function cname(name)
	return name:gsub('[^%w_]', '_'):lower()
end

local function hastypes(fields)
	for _, field in ipairs(fields) do
		if field.format then
			return true
		end
	end
	return false
end

local function decls(msg)
	local name = prefix..'_'..cname(msg.name)
	local param = ''
	if msg.input and hastypes(msg.input) then
		param = (', struct qmi_%s_request *req'):format(name)
	end
	local set = ('int qmi_set_%s_request(struct qmi_msg *msg%s)'):format(name, param)
	param = ''
	if msg.output and hastypes(msg.output) then
		param = (', struct qmi_%s_response *res'):format(name)
	end
	local parse = ('int qmi_parse_%s_response(struct qmi_msg *msg%s)'):format(name, param)
	return set, parse
end

local types = {
	gint8='int8_t',
	guint8='uint8_t',
	gint16='int16_t',
	guint16='uint16_t',
	gint32='int32_t',
	guint32='uint32_t',
	gint64='int64_t',
	guint64='uint64_t',
	gfloat='float',
	gboolean='bool',
}

local printfields

local function printtype(field)
	local type = types[field.public_format or field.format] or field.public_format
	if field.format == 'guint-sized' then
		local size = tonumber(field.guint_size)
		if size <= 2 or size > 8 then
			error('invalid size for guint-sized')
		elseif size <= 4 then
			type = 'uint32_t'
		else
			type = 'uint64_t'
		end
	end
	if type then
		p:print('%s ', type)
	elseif field.format == 'string' then
		p:print('char *')
	elseif field.format == 'sequence' or field.format == 'struct' then
		p:print('struct {\n')
		p.indent = p.indent + 1
		printfields(field.contents)
		p.indent = p.indent - 1
		p:print('} ')
	else
		error('unknown format')
	end
end

printfields = function(fields)
	for _, field in ipairs(fields) do
		if field.name then
			local name = cname(field.name)
			if field.format == 'array' then
				local size = field.fixed_size
				if size then
					printtype(field.array_element)
					print(('%s[%s];'):format(name, size))
				else
					p:print('unsigned int %s_n;\n', name)
					printtype(field.array_element)
					print(('*%s;'):format(name))
				end
			else
				printtype(field)
				print(name..';')
			end
		end
	end
end

local function printstruct(name, fields)
	print(('struct %s {'):format(name))
	print('\tstruct {')
	for _, field in ipairs(fields) do
		if field.type and field.format ~= 'string' and (field.format ~= 'array' or field.fixed_size) then
			print(('\t\tunsigned int %s : 1;'):format(cname(field.name)))
		end
	end
	print('\t} set;')
	print('\tstruct {')
	printfields(fields)
	print('\t} data;')
	print('};')
	print()
end

local put = {
	gint8='put_tlv_var(uint8_t, %s, 1);',
	guint8='put_tlv_var(uint8_t, %s, 1);',
	gint16='put_tlv_var(uint16_t, cpu_to_le16(%s), 2);',
	guint16='put_tlv_var(uint16_t, cpu_to_le16(%s), 2);',
	gint32='put_tlv_var(uint32_t, cpu_to_le32(%s), 4);',
	guint32='put_tlv_var(uint32_t, cpu_to_le32(%s), 4);',
	gint64='put_tlv_var(uint64_t, cpu_to_le64(%s), 8);',
	guint64='put_tlv_var(uint64_t, cpu_to_le64(%s), 8);',
}

local putbe = {
	gint16='put_tlv_var(uint16_t, cpu_to_be16(%s), 2);',
	guint16='put_tlv_var(uint16_t, cpu_to_be16(%s), 2);',
	gint32='put_tlv_var(uint32_t, cpu_to_be32(%s), 4);',
	guint32='put_tlv_var(uint32_t, cpu_to_be32(%s), 4);',
	gint64='put_tlv_var(uint64_t, cpu_to_be64(%s), 8);',
	guint64='put_tlv_var(uint64_t, cpu_to_be64(%s), 8);',
}

local get = {
	gint8='*(int8_t *) get_next(1)',
	guint8='*(uint8_t *) get_next(1)',
	gint16='le16_to_cpu(*(uint16_t *) get_next(2))',
	guint16='le16_to_cpu(*(uint16_t *) get_next(2))',
	gint32='le32_to_cpu(*(uint32_t *) get_next(4))',
	guint32='le32_to_cpu(*(uint32_t *) get_next(4))',
	gint64='le64_to_cpu(*(uint64_t *) get_next(8))',
	guint64='le64_to_cpu(*(uint64_t *) get_next(8))',
	gfloat='({ uint32_t data = le32_to_cpu(*(uint32_t *) get_next(4)); float _val; memcpy(&_val, &data, sizeof(_val)); _val; })'
}

local getbe = {
	gint16='be16_to_cpu(*(uint16_t *) get_next(2))',
	guint16='be16_to_cpu(*(uint16_t *) get_next(2))',
	gint32='be32_to_cpu(*(uint32_t *) get_next(4))',
	guint32='be32_to_cpu(*(uint32_t *) get_next(4))',
	gint64='be64_to_cpu(*(uint64_t *) get_next(8))',
	guint64='be64_to_cpu(*(uint64_t *) get_next(8))',
}

local function neediter(field)
	if field.format == 'array' or field.format == 'string' then
		return true
	elseif field.format == 'sequence' or field.format == 'struct' then
		for _, field in ipairs(field.contents) do
			if neediter(field) then
				return true
			end
		end
	end
	return false
end

local function printset(field, name, i)
	local s = field.endian == 'network' and putbe[field.format] or put[field.format]
	if s then
		p:print(s, name)
	elseif field.format == 'array' then
		local size = field.fixed_size
		if not size then
			size = name..'_n'
			local prefix = field.size_prefix_format or 'gint8'
			p:print(put[prefix], size)
		end
		p:print('for (%s = 0; %s < %s; %s++) {', i, i, size, i)
		if neediter(field.array_element) then
			p:print('\tunsigned int %s;', i..'i')
		end
		p.indent = p.indent + 1
		printset(field.array_element, ('%s[%s]'):format(name, i), i..'i')
		p.indent = p.indent - 1
		p:print('}')
	elseif field.format == 'string' then
		p:print('%s = %s;', i, field.fixed_size or ('strlen(%s)'):format(name))
		local size = field.max_size
		if size then
			p:print('if (%s > %s)', i, size)
			p:print('\t%s = %s;', i, size)
		end
		local prefix = field.size_prefix_format
		if not prefix and field.type ~= 'TLV' then
			prefix = 'guint8'
		end
		if prefix then
			p:print(put[prefix], i)
		end
		p:print('strncpy(__qmi_alloc_static(%s), %s, %s);', i, name, i)
	elseif field.format == 'struct' or field.format == 'sequence' then
		for _, field in ipairs(field.contents) do
			printset(field, ('%s.%s'):format(name, cname(field.name)), i)
		end
	end
end

local function printget(field, name, i)
	local s = field.endian == 'network' and getbe[field.format] or get[field.format]
	if s then
		p:print('%s = %s;', name, s)
	elseif field.format == 'array' then
		local prefix = field.size_prefix_format or 'guint8'
		local size = field.fixed_size
		if size then
			p:print('for (%s = 0; %s < %s; %s++) {', i, i, size, i)
			p.indent = p.indent + 1
			printget(field.array_element, ('%s[%s]'):format(name, i), i..'i')
			p.indent = p.indent - 1
			p:print('}')
		else
			p:print('%s = %s;', i, get[prefix])
			p:print('%s = __qmi_alloc_static(%s * sizeof(%s[0]));', name, i, name)
			p:print('while(%s-- > 0) {', i)
			p.indent = p.indent + 1
			if neediter(field.array_element) then
				p:print('unsigned int %s;', i..'i')
			end
			printget(field.array_element, ('%s[%s_n]'):format(name, name), i..'i')
			p:print('%s_n++;', name)
			p.indent = p.indent - 1
			p:print('}')
		end
	elseif field.format == 'struct' or field.format == 'sequence' then
		for _, field in ipairs(field.contents) do
			printget(field, ('%s.%s'):format(name, cname(field.name)), i)
		end
	elseif field.format == 'string' then
		local size = field.fixed_size
		if not size then
			local prefix = field.size_prefix_format
			if not prefix and field.type ~= 'TLV' then
				prefix = 'guint8'
			end
			size = prefix and get[prefix] or 'cur_tlv_len - ofs'
		end
		p:print('%s = %s;', i, size)
		if field.max_size then
			p:print('if (%s > %s)', i, field.max_size)
			p:print('\t%s = %s;', i, field.max_size)
		end
		p:print('%s = __qmi_copy_string(get_next(%s), %s);', name, i, i)
	elseif field.format == 'guint-sized' then
		local size = field.guint_size
		p:print('%s = ({ uint64_t var; memcpy(&var, get_next(%s), %s); le64_to_cpu(var); });', name, size, size)
	end
end

if what == 'header' then
	p.indent = 2
	for _, msg in ipairs(data) do
		if msg.type == 'Message' then
			local name = prefix..'_'..cname(msg.name)
			if msg.input and hastypes(msg.input) then
				printstruct(('qmi_%s_request'):format(name), msg.input)
			end
			if msg.output and hastypes(msg.output) then
				printstruct(('qmi_%s_response'):format(name), msg.output)
			end
		end
	end

	for _, msg in ipairs(data) do
		if msg.type == 'Message' then
			local set, parse = decls(msg)
			print(set..';')
			print(parse..';')
			print()
		end
	end
else
	p.endline = '\n'
	io.write[[
/* generated by uqmi gen-code.pl */
#include <stdio.h>
#include <string.h>
#include "qmi-message.h"

#define get_next(_size) ({ void *_buf = &tlv->data[ofs]; ofs += _size; if (ofs > cur_tlv_len) goto error_len; _buf; })
#define copy_tlv(_val, _size) \
	do { \
		unsigned int __size = _size; \
		if (__size > 0) \
			memcpy(__qmi_alloc_static(__size), _val, __size); \
	} while (0);

#define put_tlv_var(_type, _val, _size) \
	do { \
		_type __var = _val; \
		copy_tlv(&__var, _size); \
	} while(0)

]]

	for _, msg in ipairs(data) do
		if msg.type == 'Message' then
			local set, parse = decls(msg)

			p:print(set)
			p:print('{')
			p.indent = p.indent + 1
			p:print('qmi_init_request_message(msg, QMI_SERVICE_%s);', prefix:upper())
			p:print('msg->%s.message = cpu_to_le16(%s);', type, msg.id)
			p:print()
			if msg.input then
				for _, field in ipairs(msg.input) do
					local name = cname(field.name)
					local cond = 'set'
					if field.format == 'string' or field.format == 'array' and not field.fixed_size then
						cond = 'data'
					end
					p:print('if (req->%s.%s) {', cond, name)
					p.indent = p.indent + 1
					p:print('void *buf;')
					p:print('unsigned int ofs;')
					if neediter(field) then
						p:print('unsigned int i;')
					end
					p:print()
					p:print('__qmi_alloc_reset();')
					printset(field, 'req->data.'..name, 'i')
					p:print()
					p:print('buf = __qmi_get_buf(&ofs);')
					p:print('tlv_new(msg, %s, ofs, buf);', field.id)
					p.indent = p.indent - 1
					p:print('}')
					p:print()
				end
			end
			p:print('return 0;')
			p.indent = p.indent - 1
			p:print('}')
			p:print()

			p:print(parse)
			p:print('{')
			p.indent = p.indent + 1
			p:print('void *tlv_buf = &msg->%s.tlv;', type)
			p:print('unsigned int tlv_len = le16_to_cpu(msg->%s.tlv_len);', type)
			if hastypes(msg.output) then
				p:print('struct tlv *tlv;')
				p:print('int i;')
				p:print('uint32_t found[%d] = {};', (#msg.output + 31) / 32)
				p:print()
				p:print('memset(res, 0, sizeof(*res));')
				p:print()
				p:print('__qmi_alloc_reset();')
				p:print('while ((tlv = tlv_get_next(&tlv_buf, &tlv_len)) != NULL) {')
				p.indent = p.indent + 1
				p:print('unsigned int cur_tlv_len = le16_to_cpu(tlv->len);')
				p:print('unsigned int ofs = 0;')
				p:print()
				p:print('switch(tlv->type) {')
				local i = 1
				for _, field in ipairs(msg.output) do
					if field.format then
						local name = cname(field.name)
						p:print('case %s:', field.id)
						p.indent = p.indent + 1
						p:print('if (found[%d] & (1 << %d))', i / 32, i % 32)
						p:print('\tbreak;')
						p:print()
						p:print('found[%d] |= (1 << %d);', i / 32, i % 32)
						local s = get[field.format]
						if s then
							p:print('qmi_set(res, %s, %s);', name, s)
						elseif field.format == 'array' then
							if field.fixed_size then
								p:print('res->set.%s = 1;', name)
							end
						elseif field.format == 'sequence' or field.format == 'struct' then
							p:print('res->set.%s = 1;', name)
						end
						if not s then
							printget(field, ('res->data.%s'):format(name), 'i')
						end
						if field.format == 'array' then
							p:print()
						end
						p:print('break;')
						p.indent = p.indent - 1
						p:print()
						i = i + 1;
					end
				end
				p:print('default:')
				p:print('\tbreak;')
				p:print('}')
				p.indent = p.indent - 1
				p:print('}')
				p:print()
				p:print('return 0;')
				p:print()
				print('error_len:')
				p:print('fprintf(stderr, "%%s: Invalid TLV length in message, tlv=0x%%02x, len=%%d\\n",')
				p:print('        __func__, tlv->type, le16_to_cpu(tlv->len));')
				p:print('return QMI_ERROR_INVALID_DATA;')
			else
				p:print()
				p:print('return qmi_check_message_status(tlv_buf, tlv_len);')
			end
			p.indent = p.indent - 1
			p:print('}')
			p:print()
		end
	end
end
