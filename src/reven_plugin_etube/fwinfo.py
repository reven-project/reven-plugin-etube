import attr
import typer
import sys
from ctypes import LittleEndianStructure, BigEndianStructure, c_uint8, c_uint32, Array
from pathlib import Path
from typing import Annotated, Optional, Self
from reven.ops.pattern import Pattern
from reven.lib import Tabular, TabularColumn

DCAS_PATTERN = Pattern("ffffffff?????000?????000?????000")
DCAS_X_PATTERN = Pattern("ffffffffffffffffffffffffffffffff")
RENESAS_PATTERN = Pattern("?0??0?00??????????0?0???????????")
TI_MSP_PATTERN = Pattern("ffffffff4?0?00ff4?0?00ff??0?00ff")


model_mapping = {
    (2, 0): "SM-BMR1",
    (17, 0): "BT-DN110",
    (21, 0): "DU-E6002",
    (18, 0): "DU-E8000",
    (2, 2): "SM-EW67-A-E",
    (2, 3): "FD-6770",
    (37, 3): "FD-R9250",
    (2, 4): "RD-6770",
    (37, 4): "RD-R9250",
    (12, 2): "SC-E6010",
    (4, 2): "SM-EW90-A",
    (5, 2): "SM-EW90-B",
    (3, 6): "SM-MU70",
    (3, 7): "SM-MU75",
    (2, 1): "ST-6770",
    (37, 1): "ST-R9270",
    (3, 5): "SW-RL70",
    (16, 0): "BM-DN100",
    (37, 0): "BT-DN300",
    (34, 0): "DU-E5000",
    (8, 0): "DU-E6000",
    (255, 255): "SM-PCE1",
    (10, 0): "DU-E6001",
    (12, 0): "DU-E6001",
    (32, 0): "DU-E6100",
    (35, 0): "DU-EP800",
    (34, 2): "EW-EN100",
    (11, 0): "EW-EX010",
    (13, 0): "EW-EX020",
    (47, 0): "EW-EX310",
    (17, 2): "EW-RS910",
    (32, 1): "EW-SW100",
    (52, 2): "EW-SW310",
    (17, 8): "EW-WU101",
    (17, 10): "FC-R9100-P",
    (37, 10): "FC-R9200-P",
    (4, 3): "FD-9070",
    (16, 3): "FD-M8070",
    (9, 3): "FD-M9050",
    (45, 3): "FD-R7150",
    (17, 3): "FD-R9150",
    (6, 4): "MU-S705",
    (32, 4): "MU-UR500",
    (1, 9): "SM-PCE1",
    (15, 4): "RD-6770-A",
    (4, 4): "RD-9070",
    (16, 4): "RD-M8050",
    (46, 4): "RD-M8150-11",
    (9, 4): "RD-M9050",
    (45, 4): "RD-R7150",
    (17, 4): "RD-R9150",
    (43, 4): "RD-U6050",
    (59, 4): "RD-U8050",
    (36, 2): "SC-E5000",
    (8, 2): "SC-E6000",
    (32, 2): "SC-E6100",
    (33, 2): "SC-E7000",
    (18, 2): "SC-E8000",
    (35, 2): "SC-EM800",
    (48, 2): "SC-EN500",
    (49, 2): "SC-EN600",
    (50, 2): "SC-EN610",
    (9, 2): "SC-M9050",
    (16, 2): "SC-MT800",
    (6, 2): "SC-S705",
    (4, 9): "SM-BCR2",
    (4, 0): "SM-BMR2",
    (5, 0): "SM-BTR2",
    (4, 8): "SM-EWW01",
    (9, 6): "SM-MU71",
    (9, 7): "SM-MU76",
    (32, 9): "SM-PCE02",
    (4, 1): "ST-9070",
    (45, 1): "ST-R7170",
    (17, 1): "ST-R9150",
    (40, 1): "ST-R9250",
    (57, 1): "ST-RX825",
    (8, 1): "SW-E6000",
    (21, 1): "SW-E6010",
    (33, 1): "SW-E7000",
    (48, 1): "SW-EN600-R",
    (60, 1): "SW-EN605-R",
    (16, 1): "SW-M8050",
    (9, 1): "SW-M9050",
    (9, 5): "SW-RL71",
}
app = typer.Typer()


class Version(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [("major", c_uint8), ("minor", c_uint8), ("patch", c_uint8)]


class PackedVersion(BigEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("major", c_uint8, 4),
        ("minor", c_uint8, 4),
        ("patch", c_uint8, 8),
        ("revision", c_uint8, 8),
    ]


class DCASHeader(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("ff", c_uint32),
        ("unk_table", c_uint8 * 188),
        ("const_five", c_uint8),
        ("version", PackedVersion),
        ("unk0", c_uint8 * 2),
        ("size", c_uint32),
        ("series", c_uint8),
        ("unit", c_uint8),
        ("dcas_version", c_uint8),
        ("mcu_generation", c_uint8),
        ("unk1", c_uint8 * 2),
        ("min_app_version", Version),
        ("compat_version", PackedVersion),
    ]


class DCASXHeader(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("unk0", c_uint8 * 16),
        ("version", PackedVersion),
        ("unk1", c_uint8 * 5),
        ("size", c_uint32),
        ("unk2", c_uint8 * 12),
        ("series", c_uint8),
        ("unit", c_uint8),
        ("dcas_version", c_uint8),
        ("mcu_generation", c_uint8),
        ("min_app_version", Version),
        ("compat_version", PackedVersion),
    ]


class TIMSPHeader(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("unk0", c_uint8 * 4),
        ("version", PackedVersion),
        ("unk1", c_uint8),
        ("compat_version", PackedVersion),
        ("unk2", c_uint8),
        ("min_app_version", PackedVersion),
        ("unk3", c_uint8 * 3),
        ("size", c_uint32),
        ("unk4", c_uint8 * 2),
        ("series", c_uint8),
        ("unit", c_uint8),
    ]


class BootPatchHeader(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("checksum1", c_uint8),
        ("checksum2", c_uint8),
        ("codearea_size", c_uint8),
        ("unk0", c_uint8),
        ("dcas_version", c_uint8),
        ("mcu_generation", c_uint8),
        ("version", PackedVersion),
    ]


class RenesasHeader(LittleEndianStructure):
    _pack_ = 1
    _align_ = 1
    _fields_ = [
        ("size", c_uint32),
        ("unk0", c_uint32),
        ("version", PackedVersion),
        ("unk1", c_uint8 * 3),
        ("series", c_uint8),
        ("unit", c_uint8),
        ("compat_version", PackedVersion),
    ]


def structure_to_dict(struct: LittleEndianStructure):
    d = {}
    for x in struct._fields_:
        v = getattr(struct, x[0])
        if isinstance(v, PackedVersion):
            d[x[0]] = f"{v.major}.{v.minor}.{v.patch}.{v.revision}"
        elif isinstance(v, Version):
            d[x[0]] = f"{v.major}.{v.minor}.{v.patch}"
        elif isinstance(v, Array):
            d[x[0]] = bytes(v)
        else:
            d[x[0]] = v
    return d


def meta_readver(data: bytes) -> str:
    return f"{((data[0] & 0xF0) >> 4)}.{data[0] & 0xF}.{data[1]}.{data[2]}"


def meta_readappversion(data: bytes) -> str:
    return f"{data[0]}.{data[1]}.{data[2]}"


@attr.s(auto_attribs=True, frozen=True)
class FWInfo(Tabular):
    mcu_type: Annotated[str, TabularColumn(name="MCU Type")]
    file_type: str
    file_name: str
    model: str = "UNKNOWN"
    meta: Annotated[Optional[dict], TabularColumn(serialize=True)] = None

    def setmeta(self, data: bytes) -> Self:
        if self.file_name.startswith("Key_"):
            return self
        if self.mcu_type == "Renesas":
            header = RenesasHeader.from_buffer_copy(data)
        elif self.mcu_type in ("DCAS-X", "DCAS-2I") and self.file_type == "BootPatch":
            header = BootPatchHeader.from_buffer_copy(data)
        elif self.mcu_type in ("DCAS", "DCAS-2I"):
            header = DCASHeader.from_buffer_copy(data)
        elif self.mcu_type == "DCAS-X":
            header = DCASXHeader.from_buffer_copy(data)
        elif self.mcu_type == "TI MSP":
            header = TIMSPHeader.from_buffer_copy(data)
        else:
            header = None

        meta = {
            **(structure_to_dict(header) if header else {}),
            "et": data[-2:] == b"et",
        }
        model = self.model

        if "series" in meta and "unit" in meta:
            key = (meta["series"], meta["unit"])

            if key in model_mapping:
                model = model_mapping[key]
            else:
                print(
                    f"Series and unit of {self.file_name} is not catalogued!",
                    file=sys.stderr,
                )

        if "size" in meta and meta["size"] != len(data):
            meta["invalid"] = True
        return attr.evolve(self, meta=meta, model=model)

    def get(fw: typer.FileBinaryRead):
        file_name = Path(fw.name).name
        name = Path(fw.name).name.split(".", 2)[0]
        data = fw.read()
        if DCAS_X_PATTERN.search(data[: DCAS_X_PATTERN.bytelen]):
            file_type = "BootPatch" if name.startswith("UPDATE") else "UNKNOWN-DCAS-X"
            fwinfo = FWInfo("DCAS-X", file_type, file_name)
        elif RENESAS_PATTERN.search(data[: RENESAS_PATTERN.bytelen]):
            fwinfo = FWInfo(
                "Renesas",
                "Firmware",
                file_name,
            )
        elif TI_MSP_PATTERN.search(data[: TI_MSP_PATTERN.bytelen]):
            fwinfo = FWInfo("TI MSP", "UNKNOWN-TI-MSP", file_name)
        elif DCAS_PATTERN.search(data[: DCAS_PATTERN.bytelen]):
            file_type = "BootPatch" if name.startswith("UPDATE") else "UNKNOWN-DCAS"
            fwinfo = FWInfo("DCAS", file_type, file_name)
        elif name.startswith("UPDATE2I"):
            # no such files!
            fwinfo = FWInfo("DCAS-2I", "BootPatch", file_name)
        elif name.startswith("Key_UPDATENRF"):
            fwinfo = FWInfo("Nordic nRF", "Soft Device Key?", file_name)
        elif name.startswith("UPDATENRF"):
            if "-bt" in file_name:
                file_type = "Bootloader"
            elif "-sd" in file_name:
                file_type = "Soft Device"
            elif "-ap" in file_name:
                file_type = "Application"
            else:
                file_type = "UNKNOWN-NORDIC-NRF"
            fwinfo = FWInfo("Nordic nRF", file_type, file_name)
        else:
            fwinfo = FWInfo("UNKNOWN", "UNKNOWN", file_name)

        fwinfo = fwinfo.setmeta(data)

        if fwinfo.meta and "invalid" in fwinfo.meta and fwinfo.meta["invalid"]:
            print(f"POSSIBLY INVALID FWINFO: {file_name}", file=sys.stderr)

        return fwinfo


@app.command(help="Read the headers of E-Tube firmware files.")
def fwinfo(
    input: list[typer.FileBinaryRead],
    output: typer.FileTextWrite | None = sys.stdout,
):
    fwinfos: list[FWInfo] = [FWInfo.get(file) for file in input]
    if output:
        FWInfo.tabular_write(output, fwinfos)
    return fwinfos
