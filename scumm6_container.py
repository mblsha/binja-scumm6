# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Scumm6Container(KaitaiStruct):

    class BlockType(Enum):
        adl = 4277324
        gmd = 4672836
        rol = 5394252
        sou = 5459797
        aary = 1094799961
        apal = 1095778636
        boxd = 1112496196
        boxm = 1112496205
        cdhd = 1128548420
        char = 1128808786
        cost = 1129272148
        cycl = 1129923404
        dchr = 1145260114
        dcos = 1145261907
        dobj = 1146045002
        droo = 1146244943
        dscr = 1146307410
        dsou = 1146310485
        encd = 1162756932
        excd = 1163412292
        im00 = 1229795376
        imhd = 1229801540
        imnn = 1229811310
        lecf = 1279607622
        lflf = 1279675462
        loff = 1280263750
        lscr = 1280525138
        maxs = 1296128083
        midi = 1296647241
        nlsc = 1313624899
        obcd = 1329742660
        obim = 1329744205
        obna = 1329745473
        offs = 1330005587
        pals = 1346456659
        rmhd = 1380796484
        rmih = 1380796744
        rmim = 1380796749
        rnam = 1380860237
        room = 1380929357
        scal = 1396916556
        scrp = 1396920912
        smap = 1397571920
        soun = 1397708110
        trns = 1414680147
        verb = 1447383618
        wrap = 1465008464
        zpnn = 1515220590
    SEQ_FIELDS = ["blocks"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)
        self._read()

    def _read(self):
        self._debug['blocks']['start'] = self._io.pos()
        self.blocks = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['blocks']:
                self._debug['blocks']['arr'] = []
            self._debug['blocks']['arr'].append({'start': self._io.pos()})
            self.blocks.append(Scumm6Container.Block(self._io, self, self._root))
            self._debug['blocks']['arr'][len(self.blocks) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['blocks']['end'] = self._io.pos()

    class Boxm(KaitaiStruct):
        SEQ_FIELDS = ["v1"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['v1']['start'] = self._io.pos()
            self.v1 = self._io.read_u1()
            self._debug['v1']['end'] = self._io.pos()


    class Aary(KaitaiStruct):
        SEQ_FIELDS = ["elements"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['elements']['start'] = self._io.pos()
            self.elements = []
            i = 0
            while True:
                if not 'arr' in self._debug['elements']:
                    self._debug['elements']['arr'] = []
                self._debug['elements']['arr'].append({'start': self._io.pos()})
                _ = Scumm6Container.Aary.Element(self._io, self, self._root)
                self.elements.append(_)
                self._debug['elements']['arr'][len(self.elements) - 1]['end'] = self._io.pos()
                if _.var_no == 0:
                    break
                i += 1
            self._debug['elements']['end'] = self._io.pos()

        class Element(KaitaiStruct):
            SEQ_FIELDS = ["var_no", "xsize", "ysize", "type"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['var_no']['start'] = self._io.pos()
                self.var_no = self._io.read_u2le()
                self._debug['var_no']['end'] = self._io.pos()
                if self.var_no != 0:
                    self._debug['xsize']['start'] = self._io.pos()
                    self.xsize = self._io.read_u2le()
                    self._debug['xsize']['end'] = self._io.pos()

                if self.var_no != 0:
                    self._debug['ysize']['start'] = self._io.pos()
                    self.ysize = self._io.read_u2le()
                    self._debug['ysize']['end'] = self._io.pos()

                if self.var_no != 0:
                    self._debug['type']['start'] = self._io.pos()
                    self.type = self._io.read_u2le()
                    self._debug['type']['end'] = self._io.pos()




    class Rmih(KaitaiStruct):
        SEQ_FIELDS = ["num_z_buf"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_z_buf']['start'] = self._io.pos()
            self.num_z_buf = self._io.read_u2le()
            self._debug['num_z_buf']['end'] = self._io.pos()


    class Dobj(KaitaiStruct):
        SEQ_FIELDS = ["num_entries", "owner_state", "class_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_entries']['start'] = self._io.pos()
            self.num_entries = self._io.read_u2le()
            self._debug['num_entries']['end'] = self._io.pos()
            self._debug['owner_state']['start'] = self._io.pos()
            self.owner_state = []
            for i in range(self.num_entries):
                if not 'arr' in self._debug['owner_state']:
                    self._debug['owner_state']['arr'] = []
                self._debug['owner_state']['arr'].append({'start': self._io.pos()})
                self.owner_state.append(Scumm6Container.Dobj.OwnerState(self._io, self, self._root))
                self._debug['owner_state']['arr'][i]['end'] = self._io.pos()

            self._debug['owner_state']['end'] = self._io.pos()
            self._debug['class_data']['start'] = self._io.pos()
            self.class_data = []
            for i in range(self.num_entries):
                if not 'arr' in self._debug['class_data']:
                    self._debug['class_data']['arr'] = []
                self._debug['class_data']['arr'].append({'start': self._io.pos()})
                self.class_data.append(self._io.read_u4le())
                self._debug['class_data']['arr'][i]['end'] = self._io.pos()

            self._debug['class_data']['end'] = self._io.pos()

        class OwnerState(KaitaiStruct):
            SEQ_FIELDS = ["owner", "state"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['owner']['start'] = self._io.pos()
                self.owner = self._io.read_bits_int_le(4)
                self._debug['owner']['end'] = self._io.pos()
                self._debug['state']['start'] = self._io.pos()
                self.state = self._io.read_bits_int_le(4)
                self._debug['state']['end'] = self._io.pos()



    class UnknownBlock(KaitaiStruct):
        SEQ_FIELDS = ["data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes_full()
            self._debug['data']['end'] = self._io.pos()


    class Apal(KaitaiStruct):
        SEQ_FIELDS = ["pal"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['pal']['start'] = self._io.pos()
            self.pal = []
            for i in range(256):
                if not 'arr' in self._debug['pal']:
                    self._debug['pal']['arr'] = []
                self._debug['pal']['arr'].append({'start': self._io.pos()})
                self.pal.append(Scumm6Container.Apal.Pal(self._io, self, self._root))
                self._debug['pal']['arr'][i]['end'] = self._io.pos()

            self._debug['pal']['end'] = self._io.pos()

        class Pal(KaitaiStruct):
            SEQ_FIELDS = ["r", "g", "b"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['r']['start'] = self._io.pos()
                self.r = self._io.read_u1()
                self._debug['r']['end'] = self._io.pos()
                self._debug['g']['start'] = self._io.pos()
                self.g = self._io.read_u1()
                self._debug['g']['end'] = self._io.pos()
                self._debug['b']['start'] = self._io.pos()
                self.b = self._io.read_u1()
                self._debug['b']['end'] = self._io.pos()



    class LocalScript(KaitaiStruct):
        SEQ_FIELDS = ["index", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['index']['start'] = self._io.pos()
            self.index = self._io.read_u1()
            self._debug['index']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes_full()
            self._debug['data']['end'] = self._io.pos()


    class Cdhd(KaitaiStruct):
        SEQ_FIELDS = ["obj_id", "x", "y", "w", "h", "flags", "parent", "unknown1", "unknown2", "actor_dir"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['obj_id']['start'] = self._io.pos()
            self.obj_id = self._io.read_u2le()
            self._debug['obj_id']['end'] = self._io.pos()
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['w']['start'] = self._io.pos()
            self.w = self._io.read_u2le()
            self._debug['w']['end'] = self._io.pos()
            self._debug['h']['start'] = self._io.pos()
            self.h = self._io.read_u2le()
            self._debug['h']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u1()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['parent']['start'] = self._io.pos()
            self.parent = self._io.read_u1()
            self._debug['parent']['end'] = self._io.pos()
            self._debug['unknown1']['start'] = self._io.pos()
            self.unknown1 = self._io.read_u2le()
            self._debug['unknown1']['end'] = self._io.pos()
            self._debug['unknown2']['start'] = self._io.pos()
            self.unknown2 = self._io.read_u2le()
            self._debug['unknown2']['end'] = self._io.pos()
            self._debug['actor_dir']['start'] = self._io.pos()
            self.actor_dir = self._io.read_u1()
            self._debug['actor_dir']['end'] = self._io.pos()


    class Offs(KaitaiStruct):
        SEQ_FIELDS = ["offset"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['offset']['start'] = self._io.pos()
            self.offset = self._io.read_u4le()
            self._debug['offset']['end'] = self._io.pos()


    class Nlsc(KaitaiStruct):
        SEQ_FIELDS = ["number_local_scripts"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['number_local_scripts']['start'] = self._io.pos()
            self.number_local_scripts = self._io.read_u1()
            self._debug['number_local_scripts']['end'] = self._io.pos()


    class Rmhd(KaitaiStruct):
        SEQ_FIELDS = ["width", "height", "num_objects"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['width']['start'] = self._io.pos()
            self.width = self._io.read_u2le()
            self._debug['width']['end'] = self._io.pos()
            self._debug['height']['start'] = self._io.pos()
            self.height = self._io.read_u2le()
            self._debug['height']['end'] = self._io.pos()
            self._debug['num_objects']['start'] = self._io.pos()
            self.num_objects = self._io.read_u2le()
            self._debug['num_objects']['end'] = self._io.pos()


    class Block(KaitaiStruct):
        SEQ_FIELDS = ["block_type", "block_size", "block_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['block_type']['start'] = self._io.pos()
            self.block_type = KaitaiStream.resolve_enum(Scumm6Container.BlockType, self._io.read_u4be())
            self._debug['block_type']['end'] = self._io.pos()
            self._debug['block_size']['start'] = self._io.pos()
            self.block_size = self._io.read_u4be()
            self._debug['block_size']['end'] = self._io.pos()
            self._debug['block_data']['start'] = self._io.pos()
            _on = self.block_type
            if _on == Scumm6Container.BlockType.obcd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.rmih:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Rmih(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.obim:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.dsou:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.IndexNoOffset(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.lflf:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.maxs:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Maxs(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.wrap:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.rmim:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.dchr:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.IndexNoOffset(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.boxm:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Boxm(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.rnam:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Rnam(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.offs:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Offs(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.lscr:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.LocalScript(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.nlsc:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Nlsc(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.loff:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Loff(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.boxd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Boxd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.cdhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Cdhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.droo:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.IndexNoOffset(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im00:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.verb:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Script(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.imhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Imhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.aary:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Aary(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.scrp:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Script(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.trns:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Trns(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.dcos:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.IndexNoOffset(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.rmhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Rmhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.excd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Script(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.encd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Script(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.apal:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Apal(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.obna:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Obna(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.pals:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.dscr:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.IndexNoOffset(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.room:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.dobj:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Dobj(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.lecf:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            else:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.UnknownBlock(_io__raw_block_data, self, self._root)
            self._debug['block_data']['end'] = self._io.pos()


    class IndexNoOffset(KaitaiStruct):
        SEQ_FIELDS = ["num_entries", "index_no", "room_offset"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_entries']['start'] = self._io.pos()
            self.num_entries = self._io.read_u2le()
            self._debug['num_entries']['end'] = self._io.pos()
            self._debug['index_no']['start'] = self._io.pos()
            self.index_no = []
            for i in range(self.num_entries):
                if not 'arr' in self._debug['index_no']:
                    self._debug['index_no']['arr'] = []
                self._debug['index_no']['arr'].append({'start': self._io.pos()})
                self.index_no.append(self._io.read_u1())
                self._debug['index_no']['arr'][i]['end'] = self._io.pos()

            self._debug['index_no']['end'] = self._io.pos()
            self._debug['room_offset']['start'] = self._io.pos()
            self.room_offset = []
            for i in range(self.num_entries):
                if not 'arr' in self._debug['room_offset']:
                    self._debug['room_offset']['arr'] = []
                self._debug['room_offset']['arr'].append({'start': self._io.pos()})
                self.room_offset.append(self._io.read_u4le())
                self._debug['room_offset']['arr'][i]['end'] = self._io.pos()

            self._debug['room_offset']['end'] = self._io.pos()


    class Rnam(KaitaiStruct):
        SEQ_FIELDS = ["resource_names"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['resource_names']['start'] = self._io.pos()
            self.resource_names = []
            i = 0
            while True:
                if not 'arr' in self._debug['resource_names']:
                    self._debug['resource_names']['arr'] = []
                self._debug['resource_names']['arr'].append({'start': self._io.pos()})
                _ = Scumm6Container.Rnam.ResourceName(self._io, self, self._root)
                self.resource_names.append(_)
                self._debug['resource_names']['arr'][len(self.resource_names) - 1]['end'] = self._io.pos()
                if _.resource_id == 0:
                    break
                i += 1
            self._debug['resource_names']['end'] = self._io.pos()

        class ResourceName(KaitaiStruct):
            SEQ_FIELDS = ["resource_id", "name"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['resource_id']['start'] = self._io.pos()
                self.resource_id = self._io.read_u1()
                self._debug['resource_id']['end'] = self._io.pos()
                if self.resource_id != 0:
                    self._debug['name']['start'] = self._io.pos()
                    self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
                    self._debug['name']['end'] = self._io.pos()




    class Imhd(KaitaiStruct):
        SEQ_FIELDS = ["obj_id", "num_imnn", "num_zpnn", "unknown", "x", "y", "w", "h", "num_hotspots", "hotspots"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['obj_id']['start'] = self._io.pos()
            self.obj_id = self._io.read_u2le()
            self._debug['obj_id']['end'] = self._io.pos()
            self._debug['num_imnn']['start'] = self._io.pos()
            self.num_imnn = self._io.read_u2le()
            self._debug['num_imnn']['end'] = self._io.pos()
            self._debug['num_zpnn']['start'] = self._io.pos()
            self.num_zpnn = self._io.read_u2le()
            self._debug['num_zpnn']['end'] = self._io.pos()
            self._debug['unknown']['start'] = self._io.pos()
            self.unknown = self._io.read_u2le()
            self._debug['unknown']['end'] = self._io.pos()
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['w']['start'] = self._io.pos()
            self.w = self._io.read_u2le()
            self._debug['w']['end'] = self._io.pos()
            self._debug['h']['start'] = self._io.pos()
            self.h = self._io.read_u2le()
            self._debug['h']['end'] = self._io.pos()
            self._debug['num_hotspots']['start'] = self._io.pos()
            self.num_hotspots = self._io.read_u2le()
            self._debug['num_hotspots']['end'] = self._io.pos()
            self._debug['hotspots']['start'] = self._io.pos()
            self.hotspots = []
            for i in range(self.num_hotspots):
                if not 'arr' in self._debug['hotspots']:
                    self._debug['hotspots']['arr'] = []
                self._debug['hotspots']['arr'].append({'start': self._io.pos()})
                self.hotspots.append(Scumm6Container.Imhd.Hotspot(self._io, self, self._root))
                self._debug['hotspots']['arr'][i]['end'] = self._io.pos()

            self._debug['hotspots']['end'] = self._io.pos()

        class Hotspot(KaitaiStruct):
            SEQ_FIELDS = ["x", "y"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['x']['start'] = self._io.pos()
                self.x = self._io.read_s2le()
                self._debug['x']['end'] = self._io.pos()
                self._debug['y']['start'] = self._io.pos()
                self.y = self._io.read_s2le()
                self._debug['y']['end'] = self._io.pos()



    class Loff(KaitaiStruct):
        SEQ_FIELDS = ["num_rooms", "rooms"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_rooms']['start'] = self._io.pos()
            self.num_rooms = self._io.read_u1()
            self._debug['num_rooms']['end'] = self._io.pos()
            self._debug['rooms']['start'] = self._io.pos()
            self.rooms = []
            for i in range(self.num_rooms):
                if not 'arr' in self._debug['rooms']:
                    self._debug['rooms']['arr'] = []
                self._debug['rooms']['arr'].append({'start': self._io.pos()})
                self.rooms.append(Scumm6Container.Loff.Room(self._io, self, self._root))
                self._debug['rooms']['arr'][i]['end'] = self._io.pos()

            self._debug['rooms']['end'] = self._io.pos()

        class Room(KaitaiStruct):
            SEQ_FIELDS = ["room_id", "room_offset"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['room_id']['start'] = self._io.pos()
                self.room_id = self._io.read_u1()
                self._debug['room_id']['end'] = self._io.pos()
                self._debug['room_offset']['start'] = self._io.pos()
                self.room_offset = self._io.read_u4le()
                self._debug['room_offset']['end'] = self._io.pos()



    class Maxs(KaitaiStruct):
        SEQ_FIELDS = ["num_variables", "num_bit_variables", "num_local_objects", "num_global_objects", "num_verbs", "num_fl_object_slots", "num_arrays", "num_rooms", "num_scripts", "num_sounds", "num_costumes", "num_charsets", "num_images"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_variables']['start'] = self._io.pos()
            self.num_variables = self._io.read_u2le()
            self._debug['num_variables']['end'] = self._io.pos()
            self._debug['num_bit_variables']['start'] = self._io.pos()
            self.num_bit_variables = self._io.read_u2le()
            self._debug['num_bit_variables']['end'] = self._io.pos()
            self._debug['num_local_objects']['start'] = self._io.pos()
            self.num_local_objects = self._io.read_u2le()
            self._debug['num_local_objects']['end'] = self._io.pos()
            self._debug['num_global_objects']['start'] = self._io.pos()
            self.num_global_objects = self._io.read_u2le()
            self._debug['num_global_objects']['end'] = self._io.pos()
            self._debug['num_verbs']['start'] = self._io.pos()
            self.num_verbs = self._io.read_u2le()
            self._debug['num_verbs']['end'] = self._io.pos()
            self._debug['num_fl_object_slots']['start'] = self._io.pos()
            self.num_fl_object_slots = self._io.read_u2le()
            self._debug['num_fl_object_slots']['end'] = self._io.pos()
            self._debug['num_arrays']['start'] = self._io.pos()
            self.num_arrays = self._io.read_u2le()
            self._debug['num_arrays']['end'] = self._io.pos()
            self._debug['num_rooms']['start'] = self._io.pos()
            self.num_rooms = self._io.read_u2le()
            self._debug['num_rooms']['end'] = self._io.pos()
            self._debug['num_scripts']['start'] = self._io.pos()
            self.num_scripts = self._io.read_u2le()
            self._debug['num_scripts']['end'] = self._io.pos()
            self._debug['num_sounds']['start'] = self._io.pos()
            self.num_sounds = self._io.read_u2le()
            self._debug['num_sounds']['end'] = self._io.pos()
            self._debug['num_costumes']['start'] = self._io.pos()
            self.num_costumes = self._io.read_u2le()
            self._debug['num_costumes']['end'] = self._io.pos()
            self._debug['num_charsets']['start'] = self._io.pos()
            self.num_charsets = self._io.read_u2le()
            self._debug['num_charsets']['end'] = self._io.pos()
            self._debug['num_images']['start'] = self._io.pos()
            self.num_images = self._io.read_u2le()
            self._debug['num_images']['end'] = self._io.pos()


    class Verb(KaitaiStruct):
        SEQ_FIELDS = ["entry"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['entry']['start'] = self._io.pos()
            self.entry = []
            i = 0
            while True:
                if not 'arr' in self._debug['entry']:
                    self._debug['entry']['arr'] = []
                self._debug['entry']['arr'].append({'start': self._io.pos()})
                _ = self._io.read_u1()
                self.entry.append(_)
                self._debug['entry']['arr'][len(self.entry) - 1]['end'] = self._io.pos()
                if _ == 0:
                    break
                i += 1
            self._debug['entry']['end'] = self._io.pos()


    class Trns(KaitaiStruct):
        SEQ_FIELDS = ["transparent_color"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['transparent_color']['start'] = self._io.pos()
            self.transparent_color = self._io.read_u1()
            self._debug['transparent_color']['end'] = self._io.pos()


    class Script(KaitaiStruct):
        SEQ_FIELDS = ["data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes_full()
            self._debug['data']['end'] = self._io.pos()


    class NestedBlocks(KaitaiStruct):
        SEQ_FIELDS = ["blocks"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['blocks']['start'] = self._io.pos()
            self.blocks = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['blocks']:
                    self._debug['blocks']['arr'] = []
                self._debug['blocks']['arr'].append({'start': self._io.pos()})
                self.blocks.append(Scumm6Container.Block(self._io, self, self._root))
                self._debug['blocks']['arr'][len(self.blocks) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['blocks']['end'] = self._io.pos()


    class Obna(KaitaiStruct):
        SEQ_FIELDS = ["name"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()


    class Boxd(KaitaiStruct):
        SEQ_FIELDS = ["num_boxes", "boxes"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['num_boxes']['start'] = self._io.pos()
            self.num_boxes = self._io.read_u2le()
            self._debug['num_boxes']['end'] = self._io.pos()
            self._debug['boxes']['start'] = self._io.pos()
            self.boxes = []
            for i in range(self.num_boxes):
                if not 'arr' in self._debug['boxes']:
                    self._debug['boxes']['arr'] = []
                self._debug['boxes']['arr'].append({'start': self._io.pos()})
                self.boxes.append(Scumm6Container.Boxd.Box(self._io, self, self._root))
                self._debug['boxes']['arr'][i]['end'] = self._io.pos()

            self._debug['boxes']['end'] = self._io.pos()

        class Box(KaitaiStruct):
            SEQ_FIELDS = ["ulx", "uly", "urx", "ury", "lrx", "lry", "llx", "lly", "mask", "flags", "scale"]
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['ulx']['start'] = self._io.pos()
                self.ulx = self._io.read_s2le()
                self._debug['ulx']['end'] = self._io.pos()
                self._debug['uly']['start'] = self._io.pos()
                self.uly = self._io.read_s2le()
                self._debug['uly']['end'] = self._io.pos()
                self._debug['urx']['start'] = self._io.pos()
                self.urx = self._io.read_s2le()
                self._debug['urx']['end'] = self._io.pos()
                self._debug['ury']['start'] = self._io.pos()
                self.ury = self._io.read_s2le()
                self._debug['ury']['end'] = self._io.pos()
                self._debug['lrx']['start'] = self._io.pos()
                self.lrx = self._io.read_s2le()
                self._debug['lrx']['end'] = self._io.pos()
                self._debug['lry']['start'] = self._io.pos()
                self.lry = self._io.read_s2le()
                self._debug['lry']['end'] = self._io.pos()
                self._debug['llx']['start'] = self._io.pos()
                self.llx = self._io.read_s2le()
                self._debug['llx']['end'] = self._io.pos()
                self._debug['lly']['start'] = self._io.pos()
                self.lly = self._io.read_s2le()
                self._debug['lly']['end'] = self._io.pos()
                self._debug['mask']['start'] = self._io.pos()
                self.mask = self._io.read_u1()
                self._debug['mask']['end'] = self._io.pos()
                self._debug['flags']['start'] = self._io.pos()
                self.flags = self._io.read_u1()
                self._debug['flags']['end'] = self._io.pos()
                self._debug['scale']['start'] = self._io.pos()
                self.scale = self._io.read_u2le()
                self._debug['scale']['end'] = self._io.pos()




