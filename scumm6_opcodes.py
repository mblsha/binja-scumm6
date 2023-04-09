# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Scumm6Opcodes(KaitaiStruct):

    class OpType(Enum):
        push_byte = 0
        push_word = 1
        push_byte_var = 2
        push_word_var = 3
        byte_array_read = 6
        word_array_read = 7
        byte_array_indexed_read = 10
        word_array_indexed_read = 11
        dup = 12
        not = 13
        eq = 14
        neq = 15
        gt = 16
        lt = 17
        le = 18
        ge = 19
        add = 20
        sub = 21
        mul = 22
        div = 23
        land = 24
        lor = 25
        pop1 = 26
        write_byte_var = 66
        write_word_var = 67
        byte_array_write = 70
        word_array_write = 71
        byte_array_indexed_write = 74
        word_array_indexed_write = 75
        byte_var_inc = 78
        word_var_inc = 79
        byte_array_inc = 82
        word_array_inc = 83
        byte_var_dec = 86
        word_var_dec = 87
        byte_array_dec = 90
        word_array_dec = 91
        if = 92
        if_not = 93
        start_script = 94
        start_script_quick = 95
        start_object = 96
        draw_object = 97
        draw_object_at = 98
        draw_blast_object = 99
        set_blast_object_window = 100
        stop_object_code1 = 101
        stop_object_code2 = 102
        end_cutscene = 103
        cutscene = 104
        stop_music = 105
        freeze_unfreeze = 106
        cursor_command = 107
        break_here = 108
        if_class_of_is = 109
        set_class = 110
        get_state = 111
        set_state = 112
        set_owner = 113
        get_owner = 114
        jump = 115
        start_sound = 116
        stop_sound = 117
        start_music = 118
        stop_object_script = 119
        pan_camera_to = 120
        actor_follow_camera = 121
        set_camera_at = 122
        load_room = 123
        stop_script = 124
        walk_actor_to_obj = 125
        walk_actor_to = 126
        put_actor_at_xy = 127
        put_actor_at_object = 128
        face_actor = 129
        animate_actor = 130
        do_sentence = 131
        pickup_object = 132
        load_room_with_ego = 133
        get_random_number = 135
        get_random_number_range = 136
        get_actor_moving = 138
        is_script_running = 139
        get_actor_room = 140
        get_object_x = 141
        get_object_y = 142
        get_object_old_dir = 143
        get_actor_walk_box = 144
        get_actor_costume = 145
        find_inventory = 146
        get_inventory_count = 147
        get_verb_from_xy = 148
        begin_override = 149
        end_override = 150
        set_object_name = 151
        is_sound_running = 152
        set_box_flags = 153
        create_box_matrix = 154
        resource_routines = 155
        room_ops = 156
        actor_ops = 157
        verb_ops = 158
        get_actor_from_xy = 159
        find_object = 160
        pseudo_room = 161
        get_actor_elevation = 162
        get_verb_entrypoint = 163
        array_ops = 164
        save_restore_verbs = 165
        draw_box = 166
        pop2 = 167
        get_actor_width = 168
        wait = 169
        get_actor_scale_x = 170
        get_actor_anim_counter = 171
        sound_kludge = 172
        is_any_of = 173
        system_ops = 174
        is_actor_in_box = 175
        delay = 176
        delay_seconds = 177
        delay_minutes = 178
        stop_sentence = 179
        print_line = 180
        print_text = 181
        print_debug = 182
        print_system = 183
        print_actor = 184
        print_ego = 185
        talk_actor = 186
        talk_ego = 187
        dim_array = 188
        dummy = 189
        start_object_quick = 190
        start_script_quick2 = 191
        dim2dim_array = 192
        abs = 196
        dist_object_object = 197
        dist_object_pt = 198
        dist_pt_pt = 199
        kernel_get_functions = 200
        kernel_set_functions = 201
        delay_frames = 202
        pick_one_of = 203
        pick_one_of_default = 204
        stamp_object = 205
        get_date_time = 208
        stop_talking = 209
        get_animate_variable = 210
        shuffle = 212
        jump_to_script = 213
        band = 214
        bor = 215
        is_room_script_running = 216
        find_all_objects = 221
        get_pixel = 225
        pick_var_random = 227
        set_box_set = 228
        get_actor_layer = 236
        get_object_new_dir = 237
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.ops = []
        i = 0
        while not self._io.is_eof():
            self.ops.append(Scumm6Opcodes.Op(self._io, self, self._root))
            i += 1


    class UnknownOp(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes_full()


    class WordData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_u2le()


    class NoData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes(0)


    class ByteData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_u1()


    class Op(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.op_type = KaitaiStream.resolve_enum(Scumm6Opcodes.OpType, self._io.read_u1())
            _on = self.op_type
            if _on == Scumm6Opcodes.OpType.push_word:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_object_code2:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.lt:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.gt:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.if:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_byte_var:
                self.op_data = Scumm6Opcodes.ByteData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.add:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.div:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.jump:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_byte:
                self.op_data = Scumm6Opcodes.ByteData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.sound_kludge:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.break_here:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.sub:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.if_not:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.le:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_word_var:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.ge:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_object_code1:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_var_dec:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.mul:
                self.op_data = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.write_word_var:
                self.op_data = Scumm6Opcodes.WordData(self._io, self, self._root)
            else:
                self.op_data = Scumm6Opcodes.UnknownOp(self._io, self, self._root)



