from ctypes import (
    Array,
    BigEndianStructure,
    LittleEndianStructure,
    Structure,
    c_ubyte,
    c_uint32,
    c_uint8,
)
from pathlib import Path
from typing import Type
from io import TextIOBase
import typer

from .fwinfo import (
    DCASHeader,
    DCAS_PATTERN,
    DCASXHeader,
    DCAS_X_PATTERN,
    RenesasHeader,
    RENESAS_PATTERN,
    TIMSPHeader,
    TI_MSP_PATTERN,
)
from reven.ops.pattern import Pattern

app = typer.Typer()

DEFAULT_TYPE_NAMES: dict[Type, str] = {c_uint8: "u8", c_ubyte: "u8", c_uint32: "u32"}


def __write_type(
    type: Type,
    io: TextIOBase,
    type_names: dict[Type, str] | None = None,
):
    if type_names is None:
        type_names = dict(DEFAULT_TYPE_NAMES)

    for field in type._fields_:
        if issubclass(field[1], Array):
            if field[1]._type_ not in type_names.keys():
                __write_type(field[1]._type_, io, type_names)
        elif field[1] not in type_names.keys():
            __write_type(field[1], io, type_names)
    keyword = "bitfield" if any(len(x) == 3 for x in type._fields_) else "struct"

    print(f"{keyword} {type.__name__} {{", file=io)
    for field in type._fields_:
        fmt = "%(type)s %(name)s"
        if issubclass(field[1], Array):
            basetype = field[1]._type_
            fmt += f"[{field[1]._length_}]"
        else:
            basetype = field[1]
        if len(field) == 3:
            fmt = fmt.replace("%(type)s", "", 1).strip() + f" : {field[2]}"
        if issubclass(field[1], BigEndianStructure):
            fmt = "be " + fmt
        elif issubclass(field[1], LittleEndianStructure):
            fmt = "le " + fmt
        if basetype in type_names.keys():
            stype = type_names[basetype]
        else:
            raise Exception(f"unknown basetype {basetype}")
        print(f"\t{fmt % {'type': stype, 'name': field[0]}};", file=io)
    print("};", file=io)
    type_names[type] = f"{type.__name__}"


@app.command("hexpat", help="Generates ImHex *.hexpat files")
def hexpat(dir: Path = Path.home() / Path(".local/share/imhex/patterns")):
    d: dict[str, tuple[Pattern, Type[Structure]]] = {
        "dcas.hexpat": (DCAS_PATTERN, DCASHeader),
        "dcasx.hexpat": (DCAS_X_PATTERN, DCASXHeader),
        "renesas.hexpat": (RENESAS_PATTERN, RenesasHeader),
        "ti-msp.hexpat": (TI_MSP_PATTERN, TIMSPHeader),
    }

    print(f"Writing to {dir}:")
    for file, (pattern, header) in d.items():
        with (dir / file).open("w") as f:
            print(f"  {file}: ", end="")
            print(f"#pragma magic [ {pattern.string} ] @ 0x00", file=f)
            __write_type(header, f)
            print(f"{header.__name__} header @ 0;", file=f)
            print("OK")
