# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream
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
        nott = 13
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
        iff = 92
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

    class SubopType(Enum):
        at = 65
        color = 66
        clipped = 67
        center = 69
        left = 71
        overhead = 72
        mumble = 74
        textstring = 75
        set_costume = 76
        step_dist = 77
        sound = 78
        walk_animation = 79
        talk_animation = 80
        stand_animation = 81
        animation = 82
        init = 83
        elevation = 84
        animation_default = 85
        palette = 86
        talk_color = 87
        actor_name = 88
        init_animation = 89
        actor_width = 91
        scale = 92
        never_zclip = 93
        always_zclip = 94
        ignore_boxes = 95
        follow_boxes = 96
        animation_speed = 97
        shadow = 98
        text_offset = 99
        load_script = 100
        load_sound = 101
        load_costume = 102
        load_room = 103
        nuke_script = 104
        nuke_sound = 105
        nuke_costume = 106
        nuke_room = 107
        lock_script = 108
        lock_sound = 109
        lock_costume = 110
        lock_room = 111
        unlock_script = 112
        unlock_sound = 113
        unlock_costume = 114
        unlock_room = 115
        clear_heap = 116
        load_charset = 117
        nuke_charset = 118
        load_object = 119
        verb_image = 124
        verb_name = 125
        verb_color = 126
        verb_hicolor = 127
        verb_at = 128
        verb_on = 129
        verb_off = 130
        verb_delete = 131
        verb_new = 132
        verb_dimcolor = 133
        verb_dim = 134
        verb_key = 135
        verb_center = 136
        verb_name_str = 137
        verb_image_in_room = 139
        verb_bakcolor = 140
        save_verbs = 141
        restore_verbs = 142
        delete_verbs = 143
        cursor_on = 144
        cursor_off = 145
        userput_on = 146
        userput_off = 147
        cursor_soft_on = 148
        cursor_soft_off = 149
        userput_soft_on = 150
        userput_soft_off = 151
        cursor_image = 153
        cursor_hotspot = 154
        charset_set = 156
        charset_color = 157
        restart = 158
        pause = 159
        quit = 160
        wait_for_actor = 168
        wait_for_message = 169
        wait_for_camera = 170
        wait_for_sentence = 171
        room_scroll = 172
        room_screen = 174
        room_palette = 175
        room_shake_on = 176
        room_shake_off = 177
        room_intensity = 179
        room_savegame = 180
        room_fade = 181
        rgb_room_intensity = 182
        room_shadow = 183
        save_string = 184
        load_string = 185
        room_transform = 186
        cycle_speed = 187
        verb_init = 196
        set_current_actor = 197
        actor_variable = 198
        int_array = 199
        bit_array = 200
        nibble_array = 201
        byte_array = 202
        string_array = 203
        undim_array = 204
        assign_string = 205
        assign_int_list = 208
        assign_2dim_list = 212
        room_new_palette = 213
        cursor_transparent = 214
        actor_ignore_turns_on = 215
        actor_ignore_turns_off = 216
        neww = 217
        always_zclip_ft_demo = 225
        wait_for_animation = 226
        actor_depth = 227
        actor_walk_script = 228
        actor_stop = 229
        actor_face = 230
        actor_turn = 231
        wait_for_turn = 232
        actor_walk_pause = 233
        actor_walk_resume = 234
        actor_talk_script = 235
        baseop = 254
        endd = 255

    class VarType(Enum):
        scumm_var = 0
        local = 1
        bitvar = 2
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.op = Scumm6Opcodes.Op(self._io, self, self._root)

    class ByteArrayWrite(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u1()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class CallFuncPop2Push(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class CallFuncPop2(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)


    class Wait(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.wait_for_actor:
                self.body = Scumm6Opcodes.CallFuncPop1Word(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.wait_for_message:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.wait_for_camera:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class WordArrayRead(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class StringData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = (self._io.read_bytes_term(0, False, True, True)).decode(u"ISO-8859-1")


    class ArrayOps(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.array = self._io.read_u2le()
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.assign_string:
                self.body = Scumm6Opcodes.Message(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class ByteArrayIndexedRead(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u1()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class CallFuncPop1(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)


    class CallFuncList(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class SystemOps(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.restart:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.pause:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.quit:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class CallFuncPop3Push(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class StartScript(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class CallFuncPop3Byte(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.param = self._io.read_u1()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)


    class SetBoxFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = False
            return getattr(self, '_m_pop_list_first', None)


    class Print(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.overhead:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.baseop:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.clipped:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.mumble:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.at:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.endd:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.color:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.left:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.textstring:
                self.body = Scumm6Opcodes.Message(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.center:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class DimArray(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            self.array = self._io.read_u2le()
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.int_array:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.byte_array:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.undim_array:
                self.body = Scumm6Opcodes.CallFuncPop1Word(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.bit_array:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.nibble_array:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.string_array:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


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
            self.data = self._io.read_s2le()


    class IsAnyOf(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class CallFuncPop5(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 5
            return getattr(self, '_m_pop_count', None)


    class CallFuncPop0(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 0
            return getattr(self, '_m_pop_count', None)


    class WordArrayIndexedWrite(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class ByteArrayRead(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u1()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class JumpData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.jump_offset = self._io.read_s2le()


    class DrawBlastObject(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 5
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class ActorOps(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.follow_boxes:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.init_animation:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.palette:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.init:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.never_zclip:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.set_costume:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.set_current_actor:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.walk_animation:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.animation_speed:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.stand_animation:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.always_zclip_ft_demo:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.ignore_boxes:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.elevation:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.actor_width:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.step_dist:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.text_offset:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.talk_color:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.talk_animation:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.scale:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.always_zclip:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.actor_name:
                self.body = Scumm6Opcodes.CallFuncString(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class ByteVarData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_u1()

        @property
        def type(self):
            if hasattr(self, '_m_type'):
                return self._m_type

            self._m_type = Scumm6Opcodes.VarType.scumm_var
            return getattr(self, '_m_type', None)


    class CallFuncPop1Word(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.param = self._io.read_s2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)


    class BeginOverride(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.arg1 = self._io.read_s1()
            self.arg2 = self._io.read_s2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 0
            return getattr(self, '_m_pop_count', None)


    class VerbOps(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.verb_new:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_dim:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_color:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.endd:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_name:
                self.body = Scumm6Opcodes.Message(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_at:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_hicolor:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_delete:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_image:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_bakcolor:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_center:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_dimcolor:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_image_in_room:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_init:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_key:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.verb_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class CallFuncPop4Push(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 4
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class WordArrayIndexedRead(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class SetClass(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class WordArrayWrite(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u2le()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 2
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class NoData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes(0)


    class Word7Data(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data1 = self._io.read_s2le()
            self.data2 = self._io.read_s2le()
            self.data3 = self._io.read_s2le()
            self.data4 = self._io.read_s2le()
            self.data5 = self._io.read_s2le()
            self.data6 = self._io.read_s2le()
            self.data7 = self._io.read_s2le()


    class ByteData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_s1()


    class ResourceRoutines(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.nuke_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_room:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.nuke_costume:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_charset:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.nuke_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.unlock_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.lock_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.lock_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.lock_costume:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.nuke_room:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.unlock_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_costume:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.lock_room:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.unlock_costume:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.nuke_charset:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_object:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.load_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.unlock_room:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class CallFuncPop4(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 4
            return getattr(self, '_m_pop_count', None)


    class StartObject(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class WordVarData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bits_int_le(14)
            self.type = KaitaiStream.resolve_enum(Scumm6Opcodes.VarType, self._io.read_bits_int_le(2))


    class Message(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.parts = []
            i = 0
            while True:
                _ = Scumm6Opcodes.Message.Part(self._io, self, self._root)
                self.parts.append(_)
                if _.data == 0:
                    break
                i += 1

        class Part(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.data = self._io.read_u1()
                _on = self.data
                if _on == 0:
                    self.content = Scumm6Opcodes.Message.Part.Terminator(self._io, self, self._root)
                elif _on == 255:
                    self.content = Scumm6Opcodes.Message.Part.SpecialSequence(self._io, self, self._root)
                else:
                    self.content = Scumm6Opcodes.Message.Part.RegularChar(self.data, self._io, self, self._root)

            class Terminator(KaitaiStruct):
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._read()

                def _read(self):
                    pass


            class RegularChar(KaitaiStruct):
                def __init__(self, value, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self.value = value
                    self._read()

                def _read(self):
                    pass


            class SpecialSequence(KaitaiStruct):
                def __init__(self, _io, _parent=None, _root=None):
                    self._io = _io
                    self._parent = _parent
                    self._root = _root if _root else self
                    self._read()

                def _read(self):
                    self.code = self._io.read_u1()
                    _on = self.code
                    if _on == 14:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.SetFont(self._io, self, self._root)
                    elif _on == 10:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.Sound(self._io, self, self._root)
                    elif _on == 4:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.IntMessage(self._io, self, self._root)
                    elif _on == 6:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.NameMessage(self._io, self, self._root)
                    elif _on == 7:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.StringMessage(self._io, self, self._root)
                    elif _on == 1:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.Newline(self._io, self, self._root)
                    elif _on == 13:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.Unknown13(self._io, self, self._root)
                    elif _on == 12:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.SetColor(self._io, self, self._root)
                    elif _on == 3:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.Wait(self._io, self, self._root)
                    elif _on == 5:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.VerbMessage(self._io, self, self._root)
                    elif _on == 9:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.StartAnim(self._io, self, self._root)
                    elif _on == 2:
                        self.payload = Scumm6Opcodes.Message.Part.SpecialSequence.KeepText(self._io, self, self._root)
                    else:
                        self.payload = Scumm6Opcodes.UnknownOp(self._io, self, self._root)

                class VerbMessage(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class Wait(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        pass


                class KeepText(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        pass


                class StartAnim(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class NameMessage(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class SetColor(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class Unknown13(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class IntMessage(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class Sound(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.v1 = self._io.read_u2le()
                        self.pad1 = self._io.read_bytes(2)
                        if not self.pad1 == b"\xFF\x0A":
                            raise kaitaistruct.ValidationNotEqualError(b"\xFF\x0A", self.pad1, self._io, u"/types/message/types/part/types/special_sequence/types/sound/seq/1")
                        self.v2 = self._io.read_u2le()
                        self.pad2 = self._io.read_bytes(2)
                        if not self.pad2 == b"\xFF\x0A":
                            raise kaitaistruct.ValidationNotEqualError(b"\xFF\x0A", self.pad2, self._io, u"/types/message/types/part/types/special_sequence/types/sound/seq/3")
                        self.v3 = self._io.read_u2le()
                        self.pad3 = self._io.read_bytes(2)
                        if not self.pad3 == b"\xFF\x0A":
                            raise kaitaistruct.ValidationNotEqualError(b"\xFF\x0A", self.pad3, self._io, u"/types/message/types/part/types/special_sequence/types/sound/seq/5")
                        self.v4 = self._io.read_u2le()

                    @property
                    def value1(self):
                        if hasattr(self, '_m_value1'):
                            return self._m_value1

                        self._m_value1 = ((self.v2 << 16) | self.v1)
                        return getattr(self, '_m_value1', None)

                    @property
                    def value2(self):
                        if hasattr(self, '_m_value2'):
                            return self._m_value2

                        self._m_value2 = ((self.v4 << 16) | self.v3)
                        return getattr(self, '_m_value2', None)


                class StringMessage(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class SetFont(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        self.value = self._io.read_u2le()


                class Newline(KaitaiStruct):
                    def __init__(self, _io, _parent=None, _root=None):
                        self._io = _io
                        self._parent = _parent
                        self._root = _root if _root else self
                        self._read()

                    def _read(self):
                        pass





    class RoomOps(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.room_screen:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_shadow:
                self.body = Scumm6Opcodes.CallFuncPop5(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_fade:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.rgb_room_intensity:
                self.body = Scumm6Opcodes.CallFuncPop5(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_shake_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_palette:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_shake_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_intensity:
                self.body = Scumm6Opcodes.CallFuncPop3(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_savegame:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_transform:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_scroll:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.room_new_palette:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class CallFuncPop3(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)


    class StartScriptQuick(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)


    class CallFuncString(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")


    class CursorCommand(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.subop = KaitaiStream.resolve_enum(Scumm6Opcodes.SubopType, self._io.read_u1())
            _on = self.subop
            if _on == Scumm6Opcodes.SubopType.userput_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.userput_soft_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.userput_soft_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.charset_color:
                self.body = Scumm6Opcodes.CallFuncList(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_soft_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.charset_set:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_transparent:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_hotspot:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.userput_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_image:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_soft_on:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.SubopType.cursor_off:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class IfClassOfIs(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def pop_list(self):
            if hasattr(self, '_m_pop_list'):
                return self._m_pop_list

            self._m_pop_list = True
            return getattr(self, '_m_pop_list', None)

        @property
        def pop_list_first(self):
            if hasattr(self, '_m_pop_list_first'):
                return self._m_pop_list_first

            self._m_pop_list_first = True
            return getattr(self, '_m_pop_list_first', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class CallFuncPop1Push(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 1
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)


    class Op(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = KaitaiStream.resolve_enum(Scumm6Opcodes.OpType, self._io.read_u1())
            _on = self.id
            if _on == Scumm6Opcodes.OpType.start_object:
                self.body = Scumm6Opcodes.StartObject(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_verb_from_xy:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_anim_counter:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.end_override:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_array_indexed_write:
                self.body = Scumm6Opcodes.WordArrayIndexedWrite(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_array_indexed_write:
                self.body = Scumm6Opcodes.ByteArrayIndexedWrite(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.load_room:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_sentence:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_object_name:
                self.body = Scumm6Opcodes.Message(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.end_cutscene:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.draw_object:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.animate_actor:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_array_indexed_read:
                self.body = Scumm6Opcodes.WordArrayIndexedRead(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.create_box_matrix:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_width:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_random_number:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.land:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.find_inventory:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.delay_seconds:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_camera_at:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_word:
                self.body = Scumm6Opcodes.WordData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.begin_override:
                self.body = Scumm6Opcodes.BeginOverride(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_var_dec:
                self.body = Scumm6Opcodes.ByteVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.find_object:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_var_inc:
                self.body = Scumm6Opcodes.ByteVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.draw_blast_object:
                self.body = Scumm6Opcodes.DrawBlastObject(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_object_old_dir:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_object_code2:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.freeze_unfreeze:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.put_actor_at_object:
                self.body = Scumm6Opcodes.CallFuncPop3(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.print_debug:
                self.body = Scumm6Opcodes.Print(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.is_actor_in_box:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.lt:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_class:
                self.body = Scumm6Opcodes.SetClass(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.print_actor:
                self.body = Scumm6Opcodes.Print(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.wait:
                self.body = Scumm6Opcodes.Wait(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.save_restore_verbs:
                self.body = Scumm6Opcodes.CallFuncPop3Byte(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.gt:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.delay_minutes:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.nott:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.talk_actor:
                self.body = Scumm6Opcodes.Message(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.cutscene:
                self.body = Scumm6Opcodes.CallFuncList(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_blast_object_window:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_byte_var:
                self.body = Scumm6Opcodes.ByteData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_room:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.add:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.verb_ops:
                self.body = Scumm6Opcodes.VerbOps(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_owner:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.abs:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.dup:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.start_script_quick:
                self.body = Scumm6Opcodes.StartScriptQuick(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.face_actor:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.print_system:
                self.body = Scumm6Opcodes.Print(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.neq:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_object_y:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.walk_actor_to:
                self.body = Scumm6Opcodes.CallFuncPop3(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.div:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.pop2:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.jump:
                self.body = Scumm6Opcodes.JumpData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_array_read:
                self.body = Scumm6Opcodes.ByteArrayRead(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.draw_object_at:
                self.body = Scumm6Opcodes.CallFuncPop3(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.delay:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.room_ops:
                self.body = Scumm6Opcodes.RoomOps(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.system_ops:
                self.body = Scumm6Opcodes.SystemOps(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_byte:
                self.body = Scumm6Opcodes.ByteData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.put_actor_at_xy:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.is_sound_running:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.print_line:
                self.body = Scumm6Opcodes.Print(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.dist_pt_pt:
                self.body = Scumm6Opcodes.CallFuncPop4Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_var_inc:
                self.body = Scumm6Opcodes.WordVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.delay_frames:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.sound_kludge:
                self.body = Scumm6Opcodes.CallFuncList(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.start_sound:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_verb_entrypoint:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_object_new_dir:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_walk_box:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.is_script_running:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.break_here:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_random_number_range:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_array_indexed_read:
                self.body = Scumm6Opcodes.ByteArrayIndexedRead(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.actor_follow_camera:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.sub:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.eq:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.lor:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_object_x:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_object_script:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_state:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.print_text:
                self.body = Scumm6Opcodes.Print(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.walk_actor_to_obj:
                self.body = Scumm6Opcodes.CallFuncPop3(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_owner:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.iff:
                self.body = Scumm6Opcodes.JumpData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.start_script:
                self.body = Scumm6Opcodes.StartScript(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_array_write:
                self.body = Scumm6Opcodes.WordArrayWrite(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_costume:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.dim_array:
                self.body = Scumm6Opcodes.DimArray(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_moving:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_state:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.pan_camera_to:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.if_not:
                self.body = Scumm6Opcodes.JumpData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_array_read:
                self.body = Scumm6Opcodes.WordArrayRead(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.le:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.push_word_var:
                self.body = Scumm6Opcodes.WordVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.pickup_object:
                self.body = Scumm6Opcodes.CallFuncPop2(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_actor_scale_x:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.ge:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.byte_array_write:
                self.body = Scumm6Opcodes.ByteArrayWrite(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.cursor_command:
                self.body = Scumm6Opcodes.CursorCommand(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_object_code1:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.set_box_flags:
                self.body = Scumm6Opcodes.SetBoxFlags(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.if_class_of_is:
                self.body = Scumm6Opcodes.IfClassOfIs(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.do_sentence:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.word_var_dec:
                self.body = Scumm6Opcodes.WordVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.dist_object_pt:
                self.body = Scumm6Opcodes.CallFuncPop3Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.array_ops:
                self.body = Scumm6Opcodes.ArrayOps(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.resource_routines:
                self.body = Scumm6Opcodes.ResourceRoutines(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.pop1:
                self.body = Scumm6Opcodes.CallFuncPop1(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.dist_object_object:
                self.body = Scumm6Opcodes.CallFuncPop2Push(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.mul:
                self.body = Scumm6Opcodes.NoData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.write_word_var:
                self.body = Scumm6Opcodes.WordVarData(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.load_room_with_ego:
                self.body = Scumm6Opcodes.CallFuncPop4(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.is_any_of:
                self.body = Scumm6Opcodes.IsAnyOf(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.actor_ops:
                self.body = Scumm6Opcodes.ActorOps(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.stop_music:
                self.body = Scumm6Opcodes.CallFuncPop0(self._io, self, self._root)
            elif _on == Scumm6Opcodes.OpType.get_inventory_count:
                self.body = Scumm6Opcodes.CallFuncPop1Push(self._io, self, self._root)
            else:
                self.body = Scumm6Opcodes.UnknownOp(self._io, self, self._root)


    class ByteArrayIndexedWrite(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_func = self._io.read_bytes(0)
            self.array = self._io.read_u1()

        @property
        def pop_count(self):
            if hasattr(self, '_m_pop_count'):
                return self._m_pop_count

            self._m_pop_count = 3
            return getattr(self, '_m_pop_count', None)

        @property
        def push_count(self):
            if hasattr(self, '_m_push_count'):
                return self._m_push_count

            self._m_push_count = 1
            return getattr(self, '_m_push_count', None)



