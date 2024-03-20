# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Scumm6Container(KaitaiStruct):  # type: ignore

    class BlockType(Enum):
        adl = 4277324
        gmd = 4672836
        rol = 5394252
        sou = 5459797
        aary = 1094799961
        apal = 1095778636
        boxd = 1112496196
        boxm = 1112496205
        bstr = 1114862706
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
        im01 = 1229795377
        im02 = 1229795378
        im03 = 1229795379
        im04 = 1229795380
        im05 = 1229795381
        im06 = 1229795382
        im07 = 1229795383
        im08 = 1229795384
        im09 = 1229795385
        im10 = 1229795392
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
    def __init__(self, _io, _parent=None, _root=None):  # type: ignore
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):  # type: ignore
        self.blocks = []
        i = 0
        while not self._io.is_eof():
            self.blocks.append(Scumm6Container.Block(self._io, self, self._root))
            i += 1


    class Boxm(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.v1 = self._io.read_u1()


    class Aary(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.elements = []
            i = 0
            while True:
                _ = Scumm6Container.Aary.Element(self._io, self, self._root)
                self.elements.append(_)
                if _.var_no == 0:
                    break
                i += 1

        class Element(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.var_no = self._io.read_u2le()
                if self.var_no != 0:
                    self.xsize = self._io.read_u2le()

                if self.var_no != 0:
                    self.ysize = self._io.read_u2le()

                if self.var_no != 0:
                    self.type = self._io.read_u2le()




    class Rmih(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_z_buf = self._io.read_u2le()


    class Dobj(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_entries = self._io.read_u2le()
            self.owner_state = []
            for i in range(self.num_entries):
                self.owner_state.append(Scumm6Container.Dobj.OwnerState(self._io, self, self._root))

            self.class_data = []
            for i in range(self.num_entries):
                self.class_data.append(self._io.read_u4le())


        class OwnerState(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.owner = self._io.read_bits_int_le(4)
                self.state = self._io.read_bits_int_le(4)



    class UnknownBlock(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.data = self._io.read_bytes_full()


    class Apal(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.pal = []
            for i in range(256):
                self.pal.append(Scumm6Container.Apal.Pal(self._io, self, self._root))


        class Pal(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.r = self._io.read_u1()
                self.g = self._io.read_u1()
                self.b = self._io.read_u1()



    class LocalScript(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.index = self._io.read_u1()
            self.data = self._io.read_bytes_full()


    class Cdhd(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.obj_id = self._io.read_u2le()
            self.x = self._io.read_u2le()
            self.y = self._io.read_u2le()
            self.w = self._io.read_u2le()
            self.h = self._io.read_u2le()
            self.flags = self._io.read_u1()
            self.parent = self._io.read_u1()
            self.unknown1 = self._io.read_u2le()
            self.unknown2 = self._io.read_u2le()
            self.actor_dir = self._io.read_u1()


    class Offs(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.offset = self._io.read_u4le()


    class Nlsc(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.number_local_scripts = self._io.read_u1()


    class Rmhd(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.width = self._io.read_u2le()
            self.height = self._io.read_u2le()
            self.num_objects = self._io.read_u2le()


    class Block(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.block_type = KaitaiStream.resolve_enum(Scumm6Container.BlockType, self._io.read_u4be())
            self.block_size = self._io.read_u4be()
            _on = self.block_type
            if _on == Scumm6Container.BlockType.obcd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im02:
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
            elif _on == Scumm6Container.BlockType.im03:
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
            elif _on == Scumm6Container.BlockType.im10:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
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
            elif _on == Scumm6Container.BlockType.cost:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Cost(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.boxd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Boxd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.cdhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Cdhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im04:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im07:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
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
                self.block_data = Scumm6Container.VerbScript(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.imhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Imhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.aary:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Aary(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im08:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.bstr:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Bstr(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im06:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
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
            elif _on == Scumm6Container.BlockType.im05:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.rmhd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Rmhd(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.excd:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.Script(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im09:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
            elif _on == Scumm6Container.BlockType.im01:
                self._raw_block_data = self._io.read_bytes((self.block_size - 8))
                _io__raw_block_data = KaitaiStream(BytesIO(self._raw_block_data))
                self.block_data = Scumm6Container.NestedBlocks(_io__raw_block_data, self, self._root)
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


    class IndexNoOffset(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_entries = self._io.read_u2le()
            self.index_no = []
            for i in range(self.num_entries):
                self.index_no.append(self._io.read_u1())

            self.room_offset = []
            for i in range(self.num_entries):
                self.room_offset.append(self._io.read_u4le())



    class Cost(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.cost_size = self._io.read_u4le()
            self.header = self._io.read_u2le()
            self.num_anim = self._io.read_u1()
            self.format = self._io.read_u1()
            self.palette = []
            for i in range(self.palette_size):
                self.palette.append(self._io.read_u1())


        @property
        def palette_size(self):  # type: ignore
            if hasattr(self, '_m_palette_size'):
                return self._m_palette_size  # type: ignore

            self._m_palette_size = 16
            return getattr(self, '_m_palette_size', None)


    class Rnam(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.resource_names = []
            i = 0
            while True:
                _ = Scumm6Container.Rnam.ResourceName(self._io, self, self._root)
                self.resource_names.append(_)
                if _.resource_id == 0:
                    break
                i += 1

        class ResourceName(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.resource_id = self._io.read_u1()
                if self.resource_id != 0:
                    self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")




    class Imhd(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.obj_id = self._io.read_u2le()
            self.num_imnn = self._io.read_u2le()
            self.num_zpnn = self._io.read_u2le()
            self.unknown = self._io.read_u2le()
            self.x = self._io.read_u2le()
            self.y = self._io.read_u2le()
            self.w = self._io.read_u2le()
            self.h = self._io.read_u2le()
            self.num_hotspots = self._io.read_u2le()
            self.hotspots = []
            for i in range(self.num_hotspots):
                self.hotspots.append(Scumm6Container.Imhd.Hotspot(self._io, self, self._root))


        class Hotspot(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.x = self._io.read_s2le()
                self.y = self._io.read_s2le()



    class Loff(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_rooms = self._io.read_u1()
            self.rooms = []
            for i in range(self.num_rooms):
                self.rooms.append(Scumm6Container.Loff.Room(self._io, self, self._root))


        class Room(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.room_id = self._io.read_u1()
                self.room_offset = self._io.read_u4le()



    class Maxs(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_variables = self._io.read_u2le()
            self.num_bit_variables = self._io.read_u2le()
            self.num_local_objects = self._io.read_u2le()
            self.num_global_objects = self._io.read_u2le()
            self.num_verbs = self._io.read_u2le()
            self.num_fl_object_slots = self._io.read_u2le()
            self.num_arrays = self._io.read_u2le()
            self.num_rooms = self._io.read_u2le()
            self.num_scripts = self._io.read_u2le()
            self.num_sounds = self._io.read_u2le()
            self.num_costumes = self._io.read_u2le()
            self.num_charsets = self._io.read_u2le()
            self.num_images = self._io.read_u2le()


    class Trns(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.transparent_color = self._io.read_u1()


    class Script(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.data = self._io.read_bytes_full()


    class NestedBlocks(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.blocks = []
            i = 0
            while not self._io.is_eof():
                self.blocks.append(Scumm6Container.Block(self._io, self, self._root))
                i += 1



    class VerbScript(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.entries = []
            i = 0
            while True:
                _ = Scumm6Container.VerbScript.Entry(self._io, self, self._root)
                self.entries.append(_)
                if _.entr == 0:
                    break
                i += 1

        class Entry(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.entr = self._io.read_u1()
                if self.entr != 0:
                    self.offset = self._io.read_u2le()




    class Obna(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.name = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")


    class Bstr(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.string = []
            i = 0
            while not self._io.is_eof():
                self.string.append((self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII"))
                i += 1



    class Boxd(KaitaiStruct):  # type: ignore
        def __init__(self, _io, _parent=None, _root=None):  # type: ignore
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):  # type: ignore
            self.num_boxes = self._io.read_u2le()
            self.boxes = []
            for i in range(self.num_boxes):
                self.boxes.append(Scumm6Container.Boxd.Box(self._io, self, self._root))


        class Box(KaitaiStruct):  # type: ignore
            def __init__(self, _io, _parent=None, _root=None):  # type: ignore
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):  # type: ignore
                self.ulx = self._io.read_s2le()
                self.uly = self._io.read_s2le()
                self.urx = self._io.read_s2le()
                self.ury = self._io.read_s2le()
                self.lrx = self._io.read_s2le()
                self.lry = self._io.read_s2le()
                self.llx = self._io.read_s2le()
                self.lly = self._io.read_s2le()
                self.mask = self._io.read_u1()
                self.flags = self._io.read_u1()
                self.scale = self._io.read_u2le()




