import re
import pyPEG
from pyPEG import keyword


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
def quoted_string():        return re.compile(r"'.*?'")
def control_string():       return re.compile(r'(\#\d+)|(\#\$[a-fA-F\d]+)')
def comment():              return re.compile(r'{.*?}', re.S)


def parse(fileinput_files, trace=False):
    pyPEG.print_trace = trace
    return pyPEG.parse(unit(), fileinput_files, skipWS=True, skipComments=comment)


if __name__ == '__main__':
    import fileinput
    files = fileinput.input()
    result = parse(files)
    print result
