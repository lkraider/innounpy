import re
import sys
import json
import pyPEG
from pyPEG import keyword

try:
    from collections import OrderedDict
except:
    from ordereddict import OrderedDict


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


def pyast_to_json(ast, raw_dump=False):
    pyast_dict = pyast_to_dict(ast)
    if raw_dump:
        return json.dumps(pyast_dict)
    formatter = StructFormatter(pyast_dict)
    return json.dumps(formatter.format())


class StructFormatter(object):
    """
    Format pyAST to easily parseable dictionary collection.

    Note: for structures that contain strings interpret its size as
    minimum size, not actual, since strings are variable in length.
    """

    def __init__(self, pyast_dict):
        self.pyast_dict = pyast_dict
        self._output = OrderedDict()

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
        'char': 1, 'ansichar': 1, 'widechar': 2,
        'string': [4, 1], # has an integer header that stores its length
        'ansistring': [4, 1], 'widestring': [4, 2],
    }

    type_values = {
        'boolean': 2,
        'byte': 256, 'char': 256, 'ansichar': 256,
        'word': 65536,
    }

    def _array_type(self, array_dict):
        """Return (subtype_dict, count, size) of array"""
        index = array_dict['array_index']
        if 'identifier' in index:
            indextype_id = index['identifier']
            type_data = self._output.get(indextype_id)
            if type_data:
                count = type_data.get('count') or self.type_values.get(type_data['type'])
            else:
                count = self.type_values[indextype_id.lower()]
        elif 'expression' in index:
            assert(len(index['expression']) > 1)
            i0 = int(index['expression'][0]['int_num'])
            i1 = int(index['expression'][1]['int_num'])
            count = i1 - i0 + 1
        subtype_data = self._format_types(array_dict['array_subtype'])
        if subtype_data:
            subtype = subtype_data
            subtype_size = subtype_data['size']
        else:
            subtype_id = array_dict['array_subtype']['type_id']
            subtype_size = self.type_sizes[subtype_id.lower()]
            subtype = subtype_id.lower()
        # ignore string size since it is variable
        size = (count * subtype_size) if not isinstance(subtype_size, list) else None
        return subtype, count, size

    def _enum_type(self, enum_dict):
        """Return (count, size) of enum"""
        if isinstance(enum_dict['identifier'], list):
            count = len(enum_dict['identifier'])
            size = 1 if count < 256 else 2
            return count, size
        return 1, 1

    def _set_type(self, set_dict):
        """Return (subtype_dict, size) of set"""
        subtype = self._format_types(set_dict)
        size = subtype.get('count') or self.type_values.get(subtype['type']) - 1
        size = (size / 8) + 1
        return subtype, size

    def _record_type(self, record_dict):
        """Return (fields_list, size) of record"""
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
                        sys.stderr.write('could not calculate field size for type: %s\n' % n)
        return fields, size

    def _format_types(self, type_dict):
        """Type declaration formatter"""
        td = type_dict
        t = {}
        if 'type_id' in td:
            type_id = td['type_id']
            type_data = self._output.get(type_id)
            if type_data:
                t = type_data
            else:
                t['size'] = self.type_sizes.get(type_id.lower())
                t['type'] = type_id if not t['size'] else type_id.lower()
        elif 'array_type' in td:
            t['type'] = u'array'
            t['subtype'], t['count'], t['size'] = self._array_type(td['array_type'])
        elif 'enum_type' in td:
            t['type'] = u'enum'
            t['count'], t['size'] = self._enum_type(td['enum_type'])
        elif 'set_type' in td:
            t['type'] = u'set'
            t['subtype'], t['size'] = self._set_type(td['set_type'])
        elif 'record_decl' in td:
            t['type'] = u'record'
            t['fields'], t['size'] = self._record_type(td['record_decl'])
        elif 'pointer_type' in td:
            pass # ignore pointer types
        elif 'expression' in td:
            pass # ignore const declarations
        else:
            sys.stderr.write('could not format type: %s\n' % type_dict)
        return t

    def _format_values(self, const_expression):
        """Const declaration formatter"""
        e = const_expression
        v = None
        if isinstance(e, list):
            v = []
            for item in e:
                v.append(self._format_values(item))
        if 'expression' in e:
            v = self._format_values(e['expression'])
        if 'quoted_string' in e or 'control_string' in e:
            v = ''
            for k,s in e.items():
                if '_string' not in k:
                    continue
                if not isinstance(s, list):
                    s = [s]
                unquote = (lambda s: s[1:-1]) if k == 'quoted_string' else (lambda s: s)
                v += str.join('', map(unquote, s)) # assumes string concatenation
        elif 'add_op' in e or 'mul_op' in e:
            v = self._reduce_values(e, v)
        elif 'int_num' in e:
            v = int(e['int_num'])
        elif 'hex_num' in e:
            v = e['hex_num']
        elif v is None:
            sys.stderr.write('could not format const: %s\n' % const_expression)
        return v

    def _reduce_values(self, const_expression, current_value):
        e = const_expression
        v = current_value
        if v:
            # assumptions here:
            # - `e[0]` is an expression
            # - `e[1]` is an operator
            # - `e[2]` is an operand
            # - `v` is output of `e[0]` expression
            # - `v` is same type as `e[2]`
            operators, operands = e.items()[1:]
            if not isinstance(v, list):
                v = [v]
        else:
            operands, operators = e.items()
        operand_type, operands = operands
        operator_type, operators = operators
        if not isinstance(operands, list):
            operands = [operands]
        if not isinstance(operators, list):
            operators = [operators]
        if v:
            operands = v + operands
        if operand_type == 'int_num':
            operands = map(int, operands)
        else:
            sys.stderr.write('unprocessed operand type: %s\n' % operand_type)
        if operator_type in ['mul_op', 'add_op']:
            v = operands[0]
            for i,o in zip(operands[1:], operators):
                if o == 'shl':
                    v = v << i
                elif o == '+':
                    v += i
                else:
                    sys.stderr.write('uhandled operation: %s %s %s\n' % (v, o, i))
        else:
            sys.stderr.write('uprocessed operation type: %s\n' % operator_type)
        return v

    def format(self):
        for ts in self.pyast_dict['unit_interface']['type_section']:
            if isinstance(ts['type_declaration'], dict):
                ts['type_declaration'] = [ts['type_declaration']]
            for td in ts['type_declaration']:
                name = td['identifier']
                t = self._format_types(td)
                if t:
                    self._output[name] = t
        for cs in self.pyast_dict['unit_interface']['const_section']:
            if isinstance(cs['const_declaration'], dict):
                cs['const_declaration'] = [cs['const_declaration']]
            for cd in cs['const_declaration']:
                name = cd['identifier']
                c = self._format_types(cd)
                c['value'] = self._format_values(cd['expression'])
                self._output[name] = c
        unit_dict = {self.pyast_dict['unit_head']['identifier']: self._output}
        return unit_dict


if __name__ == '__main__':
    import fileinput
    files = fileinput.input()
    result = parse(files)
    print pyast_to_json(result)
