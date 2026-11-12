"""从独立 MSVC COFF 归档生成 FH4 配置，不读取待分析程序。"""
import argparse
import collections
import hashlib
import json
import pathlib
import struct


def objects(path):
    data = path.read_bytes()
    if data[:8] != b'!<arch>\n':
        raise ValueError('需要 COFF 归档')
    position = 8
    while position + 60 <= len(data):
        header = data[position:position + 60]
        size = int(header[48:58])
        body = data[position + 60:position + 60 + size]
        position += 60 + size + (size & 1)
        if body[:2] == b'\x64\x86':
            yield parse(body)


def parse(data):
    _, count, _, symbols_at, symbol_count, optional, _ = struct.unpack_from('<HHIIIHH', data)
    strings = symbols_at + symbol_count * 18

    def name(raw):
        if raw[:4] == b'\0' * 4:
            start = strings + struct.unpack_from('<I', raw, 4)[0]
            return data[start:data.index(0, start)].decode('utf-8')
        return raw.rstrip(b'\0').decode('ascii')

    symbols = {}
    index = 0
    while index < symbol_count:
        raw, value, section, _, storage, auxiliary = struct.unpack_from('<8sIhHBB', data, symbols_at + index * 18)
        symbols[index] = (name(raw), value, section, storage)
        index += 1 + auxiliary
    sections = []
    for index in range(count):
        _, _, _, size, raw_at, rel_at, _, rel_count, _, flags = struct.unpack_from('<8sIIIIIIHHI', data, 20 + optional + index * 40)
        relocations = []
        for entry in range(rel_count):
            offset, symbol, kind = struct.unpack_from('<IIH', data, rel_at + entry * 10)
            relocations.append((offset, kind, symbols[symbol]))
        sections.append(dict(data=data[raw_at:raw_at + size] if raw_at else b'\0' * size,
                             relocations=relocations, executable=bool(flags & 0x20)))
    return dict(symbols=symbols, sections=sections)


def generate(paths):
    modules = list(objects(paths[0]))
    definitions = collections.defaultdict(list)
    leaves = collections.defaultdict(list)

    def index_symbols(target, first, items):
        for offset, module in enumerate(items):
            for name, value, section, storage in module['symbols'].values():
                if section > 0 and storage == 2:
                    target[name].append((first + offset, section - 1, value))

    index_symbols(definitions, 0, modules)
    for path in paths[1:]:
        extra = list(objects(path))
        index_symbols(leaves, len(modules), extra)
        modules.extend(extra)
    preferred = {'??0bad_exception@std@@QEAA@XZ', '??1bad_exception@std@@UEAA@XZ',
                 '??0bad_exception@std@@QEAA@AEBV01@@Z'}
    for name in preferred:
        if leaves[name]:
            definitions[name] = leaves[name]
    for name in ['??_Eexception@std@@UEAAPEAXI@Z', '??_Ebad_exception@std@@UEAAPEAXI@Z']:
        leaves[name] = leaves[name.replace('??_E', '??_G')]
    nodes = {}

    def visit(module_index, section_index, closed_math=False):
        key = f'{module_index}:{section_index}' + (':math' if closed_math else '')
        if key in nodes:
            return key
        section = modules[module_index]['sections'][section_index]
        raw = bytearray(section['data'])
        node = dict(Executable=section['executable'], Length=len(raw), Hash='', Relocations=[])
        nodes[key] = node
        for offset, kind, symbol in section['relocations']:
            if kind not in (1, 3, 4, 5, 6, 7, 8, 9):
                raise ValueError(f'运行库闭包含不支持的 AMD64 重定位：{kind}')
            width = 8 if kind == 1 else 4
            addend = int.from_bytes(raw[offset:offset + width], 'little', signed=kind >= 4)
            raw[offset:offset + width] = b'\0' * width
            name, value, local_section, _ = symbol
            target = None
            if closed_math and name == '__security_check_cookie':
                # 栈破坏检查沿用独立 CRT 边界，不把全局异常上下文当作数学常量。
                pass
            elif closed_math and local_section <= 0 and name in leaves and name not in {
                    '__isa_available', '__isa_enabled', '__favor', '__use_fma3_lib', '__security_cookie',
                    '__guard_check_icall_fptr', '__guard_dispatch_icall_fptr'}:
                owner, member, value = leaves[name][0]
                target = visit(owner, member, True)
            elif name in preferred or local_section <= 0 and name in definitions:
                owner, member, value = definitions[name][0]
                target = visit(owner, member, closed_math)
            elif local_section > 0:
                target = visit(module_index, local_section - 1, closed_math)
            node['Relocations'].append(dict(Offset=offset, Kind=kind, Addend=addend,
                                            Value=value, Target=target, Symbol=name))
        node['Hash'] = hashlib.sha256(raw).hexdigest().upper()
        return key

    roots = {name: visit(*definitions[name][0][:2]) for name in ['__CxxFrameHandler4', '_CxxThrowException']}
    for name in ['modf', 'powf', 'acosf', 'cosf', 'sinf', 'sqrtf']:
        roots[name] = visit(*leaves[name][0][:2], closed_math=True)
    roots['memset'] = visit(*definitions['memset'][0][:2], closed_math=True)
    boundaries = {}
    names = {r['Symbol'] for n in nodes.values() for r in n['Relocations'] if r['Target'] is None}
    control_names = {'free', '_free_base', '_invoke_watson', '__std_terminate', 'terminate'}
    names |= control_names
    for name in sorted(names):
        variants = {}
        sources = leaves[name] + (definitions[name] if name in control_names else [])
        for owner, member, value in sources:
            section = modules[owner]['sections'][member]
            if any(kind not in (1, 3, 4, 5, 6, 7, 8, 9) for _, kind, _ in section['relocations']):
                continue
            raw = bytearray(section['data'][value:])
            relocations = []
            for offset, kind, _ in section['relocations']:
                if offset < value:
                    continue
                offset -= value
                width = 8 if kind == 1 else 4
                raw[offset:offset + width] = b'\0' * width
                relocations.append(dict(Offset=offset, Kind=kind))
            variant = dict(Executable=section['executable'], Length=len(raw),
                           Hash=hashlib.sha256(raw).hexdigest().upper(), Relocations=relocations)
            variants[json.dumps(variant, sort_keys=True)] = variant
        if variants:
            boundaries[name] = list(variants.values())
    for key, node in nodes.items():
        owner, member = map(int, key.split(':')[:2])
        names = {s[0] for s in modules[owner]['symbols'].values() if s[2] == member + 1}
        reference = bytearray(modules[owner]['sections'][member]['data'])
        for relocation in node['Relocations']:
            width = 8 if relocation['Kind'] == 1 else 4
            reference[relocation['Offset']:relocation['Offset'] + width] = b'\0' * width
        # 标准异常类内联体的独立指令重排；调用之前的同址清零、vptr 写入和参数值保持相同。
        if '??0exception@std@@QEAA@AEBV01@@Z' in names:
            if reference != bytes.fromhex('40534883EC20488BD9488BC2488D0D000000000F57C048890B488D5308488D48080F1102E800000000488BC34883C4205BC3'):
                continue
            raw = bytes.fromhex('40534883EC20488BC2488BD9488D0D0000000048890B0F57C00F114308488D5308488D4808E800000000488BC34883C4205BC3')
            rel = [dict(r, Offset=r['Offset'] + (1 if r['Offset'] >= 37 else 0)) for r in node['Relocations']]
        elif '?what@exception@std@@UEBAPEBDXZ' in names:
            if reference != bytes.fromhex('4883790800488D0500000000480F454108C3'):
                continue
            # 成员非空返回成员，否则返回同一只读字符串；已构造异常对象的两种等价选择形态。
            raw = bytes.fromhex('48837908007405488B4108C3488D0500000000C3')
            rel = [dict(r, Offset=15) for r in node['Relocations']]
        else:
            continue
        node['Alternatives'] = [dict(Executable=True, Length=len(raw), Hash=hashlib.sha256(raw).hexdigest().upper(), Relocations=rel)]
    return dict(Contract='MSVC-14.44-x64-FH4', Root=roots['__CxxFrameHandler4'], Roots=roots, Nodes=nodes,
                Boundaries=boundaries, Sources=[dict(Library=p.name, Sha256=hashlib.sha256(p.read_bytes()).hexdigest().upper()) for p in paths])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vcruntime', type=pathlib.Path)
    parser.add_argument('cpprt', type=pathlib.Path)
    parser.add_argument('crt', type=pathlib.Path)
    parser.add_argument('ucrt', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    options = parser.parse_args()
    result = generate([options.vcruntime, options.cpprt, options.crt, options.ucrt])
    options.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
