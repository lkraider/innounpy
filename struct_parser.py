import re
import json
import pyPEG
from pyPEG import keyword
from collections import OrderedDict


# A simplified pascal unit grammar, specialized in parsing Inno Setup Struct.pas files

def unit():                 return unit_head, unit_interface, _unit_implementation, _unit_block, '.'
def unit_head():            return keyword('unit'), identifier, ';'
def unit_interface():       return keyword('interface'), 0, uses_clause, -1, _decl_section
def _unit_implementation(): return keyword('implementation'), 0, uses_clause, -1, _decl_section
def _unit_block():          return keyword('end')
def uses_clause():          return keyword('uses'), _ident_list, ';'
def _decl_section():        return [const_section, type_section]
def const_section():        return keyword('const'), -2, const_declaration
def const_declaration():    return identifier, 0, (':', _type_decl), '=', _const_expression, ';'
def type_section():         return keyword('type'), -2, type_declaration
def type_declaration():     return identifier, '=', _type_decl, ';'
def _type_decl():           return [_struc_type, pointer_type, _variant_type, _simple_type, (keyword('type'), type_id)]
def _struc_type():          return 0, keyword('packed'), [array_type, set_type, record_decl]
def array_type():           return keyword('array'), 0, ('[', 0, array_index, -1, (',', array_index), ']'), keyword('of'), array_subtype
def array_index():          return [identifier, (_const_expression, '..', _const_expression)]
def array_subtype():        return [keyword('const'), _type_decl]
def set_type():             return keyword('set'), keyword('of'), _type_decl
def pointer_type():         return '^', _type_decl
def _variant_type():        return type_id
def _simple_type():         return [type_id, subrange_type, enum_type]
def subrange_type():        return _const_expression, 0, ('..', _const_expression)
def enum_type():            return '(', identifier, 0, ('=', expression), -1, (',', identifier, 0, ('=', expression)), ')'
def record_decl():          return keyword('record'), -1, record_field, -1, record_item, keyword('end')
def record_item():          return [const_section, type_section, record_field]
def record_field():         return _ident_list, ':', _type_decl, ';'
def expression():           return _term, -1, (add_op, _term)
def _term():                return _factor, -1, (mul_op, _factor)
def _factor():              return [('not', _factor), ('+', _factor), ('-', _factor), ('^', identifier), int_num, real_num, hex_num, asm_hex_num, 'true', 'false', 'nil', ('(', expression, ')'), _string_factor, set_section, (identifier, '(', expression, ')')]
def _string_factor():       return -2, [quoted_string, control_string]
def set_section():          return '[', 0, (expression, -1, ([',', '..'], expression)), ']'
def colon_construct():      return ':', expression, 0, (':', expression)
def _const_expression():    return [expression, ('(', _const_expression, -1, (',', _const_expression), ')')]
def _ident_list():          return identifier, -1, (',', identifier)

def add_op():               return re.compile(r'\+|\-|or|xor')
def mul_op():               return re.compile(r'\*|\/|div|mod|and|shl|shr|as')
def identifier():           return re.compile(r'[a-zA-Z_]\w*')
def type_id():              return re.compile(r'[a-zA-Z_]\w*')
def int_num():              return re.compile(r'\d+')
def real_num():             return re.compile(r'd+(\.\d*)?([eE]([+-])?d+)?')
def hex_num():              return re.compile(r'\$[a-fA-F\d]+')
def asm_hex_num():          return re.compile(r'[a-fA-F\d]+[hH]?')
def quoted_string():        return re.compile(r"'[^'\n]*'")
def control_string():       return re.compile(r'(\#\d+)|(\#\$[a-fA-F\d]+)')
def comment():              return re.compile(r'{.*?}', re.S)


def parse(fileinput_files, trace=False):
    pyPEG.print_trace = trace
    return pyPEG.parse(unit(), fileinput_files, skipWS=True, skipComments=comment)


def pyast_to_dict(ast):
    ast_dict = OrderedDict()

    def add_or_append(d, key, val):
        if key in d:
            if type(d[key]) == list:
                d[key].append(val)
            else:
                d[key] = [d[key], val]
        else:
            d[key] = val

    def todict(l, d):
        if type(l) == list:
            for i in l:
                todict(i, d)
        elif type(l) == pyPEG.Symbol:
            key = l.__name__
            if isinstance(l.what, basestring):
                add_or_append(d, key, l.what)
            else:
                nd = OrderedDict()
                add_or_append(d, key, nd)
                todict(l.what, d=nd)

    todict(ast, ast_dict)
    return ast_dict


def pyast_to_json(ast):
    return json.dumps(pyast_to_dict(ast))


class StructFormatter(object):

    def __init__(self, pyast_dict):
        self.pyast_dict = pyast_dict
        self._output = {}

    # size definitions
    type_sizes = {
        # integer types
        'byte': 1, 'boolean': 1, 'shortint': 1,
        'smallint': 2, 'word': 2,
        'integer': 4, 'cardinal': 4, 'longint': 4, 'longword': 4, 'dword': 4,
        'integer64': 8, 'qword': 8,
        # real types
        'real': 4, 'single': 4,
        'double': 8, 'extended': 10,
        # string types
        'char': 1, 'widechar': 2,
        'string': [4, 1], # has an integer header that stores its length
        'ansistring': [4, 1], 'widestring': [4, 2],
    }

    def _array_type(self, array_dict):
        size = 0
        if len(array_dict['array_index']['expression']) > 1:
            i0 = int(array_dict['array_index']['expression'][0]['int_num'])
            i1 = int(array_dict['array_index']['expression'][1]['int_num'])
            size = i1 - i0 + 1
        subtype = array_dict['array_subtype']['type_id'].lower()
        return subtype, size * self.type_sizes.get(subtype, subtype)

    def _enum_type(self, enum_dict):
        if isinstance(enum_dict['identifier'], list):
            return len(enum_dict['identifier'])
        return 1

    def _set_type(self, set_dict):
        subtype = self._format_types(set_dict)
        size = subtype['size']
        size = (size / 8) + 1
        return subtype, size

    def _record_type(self, record_dict):
        if isinstance(record_dict['record_field'], dict):
            record_dict['record_field'] = [record_dict['record_field']]
        size = 0
        fields = OrderedDict()
        for field in record_dict['record_field']:
            name = field['identifier']
            t = self._format_types(field)
            if t:
                if not isinstance(name, list):
                    name = [name]
                for n in name:
                    fields[n] = t
                    try:
                        size += t['size'] if not isinstance(t['size'], list) else t['size'][0]
                    except Exception:
                        print 'field size error', n, t['size']
        return fields, size

    def _format_types(self, type_dict):
        td = type_dict
        t = {}
        # type formatters
        if 'type_id' in td:
            type_id = td['type_id']
            type_data = self._output.get(type_id)
            if type_data is None:
                type_name = type_id.lower()
            else:
                type_name = type_data['type']
            size = self._output.get(td['type_id'], {}).get('size')
            if size is None:
                size = self.type_sizes.get(type_id.lower())
                type_name = type_id if size is None else type_name
            t['type'] = type_name
            t['size'] = size
            subtype = type_data.get('subtype') if type_data else None
            fields = type_data.get('fields') if type_data else None
            if subtype is not None:
                t['subtype'] = subtype
            if fields is not None:
                t['fields'] = fields
        if 'array_type' in td:
            t['type'] = u'array'
            t['subtype'], t['size'] = self._array_type(td['array_type'])
        elif 'enum_type' in td:
            t['type'] = u'enum'
            t['size'] = self._enum_type(td['enum_type'])
        elif 'set_type' in td:
            t['type'] = u'set'
            t['subtype'], t['size'] = self._set_type(td['set_type'])
        elif 'record_decl' in td:
            t['type'] = u'record'
            t['fields'], t['size'] = self._record_type(td['record_decl'])
        elif 'pointer_type' in td:
            pass # ignore pointer types
        return t

    def format(self):
        for ts in self.pyast_dict['unit_interface']['type_section']:
            if isinstance(ts['type_declaration'], dict):
                continue
            for td in ts['type_declaration']:
                name = td['identifier']
                t = self._format_types(td)
                if t:
                    self._output[name] = t
        unit_dict = {self.pyast_dict['unit_head']['identifier']: self._output}
        return unit_dict


if __name__ == '__main__':
    import fileinput
    from pprint import pprint
    files = fileinput.input()
    result = parse(files)
    pyast_dict = pyast_to_dict(result)
    s = StructFormatter(pyast_dict)
    print json.dumps(s.format())
