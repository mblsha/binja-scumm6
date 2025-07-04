meta:
  id: scumm6_opcodes
  file-extension: scumm6_opcodes
  endian: le
  bit-endian: le # used for bit-fields

seq:
  - id: op
    type: op
    # repeat: eos

enums:
  # ScummEngine_v6::setupOpcodes()
  # https://github.com/scummvm/scummvm/blob/master/engines/scumm/script_v6.cpp
  op_type:
    0x00: push_byte
    0x01: push_word
    0x02: push_byte_var
    0x03: push_word_var
    0x06: byte_array_read
    0x07: word_array_read
    0x0a: byte_array_indexed_read
    0x0b: word_array_indexed_read
    0x0c: dup
    0x0d: nott
    0x0e: eq
    0x0f: neq
    0x10: gt
    0x11: lt
    0x12: le
    0x13: ge
    0x14: add
    0x15: sub
    0x16: mul
    0x17: div
    0x18: land
    0x19: lor
    0x1a: pop1
    0x42: write_byte_var
    0x43: write_word_var
    0x46: byte_array_write
    0x47: word_array_write
    0x4a: byte_array_indexed_write
    0x4b: word_array_indexed_write
    0x4e: byte_var_inc
    0x4f: word_var_inc
    0x52: byte_array_inc
    0x53: word_array_inc
    0x56: byte_var_dec
    0x57: word_var_dec
    0x5a: byte_array_dec
    0x5b: word_array_dec
    0x5c: iff
    0x5d: if_not
    0x5e: start_script
    0x5f: start_script_quick
    0x60: start_object
    0x61: draw_object
    0x62: draw_object_at
    0x63: draw_blast_object
    0x64: set_blast_object_window
    0x65: stop_object_code1
    0x66: stop_object_code2
    0x67: end_cutscene
    0x68: cutscene
    0x69: stop_music
    0x6a: freeze_unfreeze
    0x6b: cursor_command
    0x6c: break_here
    0x6d: if_class_of_is
    0x6e: set_class
    0x6f: get_state
    0x70: set_state
    0x71: set_owner
    0x72: get_owner
    0x73: jump
    0x74: start_sound
    0x75: stop_sound
    0x76: start_music
    0x77: stop_object_script
    0x78: pan_camera_to
    0x79: actor_follow_camera
    0x7a: set_camera_at
    0x7b: load_room
    0x7c: stop_script
    0x7d: walk_actor_to_obj
    0x7e: walk_actor_to
    0x7f: put_actor_at_xy
    0x80: put_actor_at_object
    0x81: face_actor
    0x82: animate_actor
    0x83: do_sentence
    0x84: pickup_object
    0x85: load_room_with_ego
    0x87: get_random_number
    0x88: get_random_number_range
    0x8a: get_actor_moving
    0x8b: is_script_running
    0x8c: get_actor_room
    0x8d: get_object_x
    0x8e: get_object_y
    0x8f: get_object_old_dir
    0x90: get_actor_walk_box
    0x91: get_actor_costume
    0x92: find_inventory
    0x93: get_inventory_count
    0x94: get_verb_from_xy
    0x95: begin_override
    0x96: end_override
    0x97: set_object_name
    0x98: is_sound_running
    0x99: set_box_flags
    0x9a: create_box_matrix
    0x9b: resource_routines
    0x9c: room_ops
    0x9d: actor_ops
    0x9e: verb_ops
    0x9f: get_actor_from_xy
    0xa0: find_object
    0xa1: pseudo_room
    0xa2: get_actor_elevation
    0xa3: get_verb_entrypoint
    0xa4: array_ops
    0xa5: save_restore_verbs
    0xa6: draw_box
    0xa7: pop2
    0xa8: get_actor_width
    0xa9: wait
    0xaa: get_actor_scale_x
    0xab: get_actor_anim_counter
    0xac: sound_kludge
    0xad: is_any_of
    0xae: system_ops
    0xaf: is_actor_in_box
    0xb0: delay
    0xb1: delay_seconds
    0xb2: delay_minutes
    0xb3: stop_sentence
    0xb4: print_line
    0xb5: print_text
    0xb6: print_debug
    0xb7: print_system
    0xb8: print_actor
    0xb9: print_ego
    0xba: talk_actor
    0xbb: talk_ego
    0xbc: dim_array
    0xbd: dummy
    0xbe: start_object_quick
    0xbf: start_script_quick2
    0xc0: dim2dim_array
    0xc4: abs
    0xc5: dist_object_object
    0xc6: dist_object_pt
    0xc7: dist_pt_pt
    0xc8: kernel_get_functions
    0xc9: kernel_set_functions
    0xca: delay_frames
    0xcb: pick_one_of
    0xcc: pick_one_of_default
    0xcd: stamp_object
    0xd0: get_date_time
    0xd1: stop_talking
    0xd2: get_animate_variable
    0xd4: shuffle
    0xd5: jump_to_script
    0xd6: band
    0xd7: bor
    0xd8: is_room_script_running
    0xdd: find_all_objects
    0xe1: get_pixel
    0xe3: pick_var_random
    0xe4: set_box_set
    0xec: get_actor_layer
    0xed: get_object_new_dir

  subop_type:
    65: at
    66: color
    67: clipped
    69: center
    71: left
    72: overhead
    74: mumble
    75: textstring
    76: set_costume
    77: step_dist
    78: sound
    79: walk_animation
    80: talk_animation
    81: stand_animation
    82: animation
    83: init
    84: elevation
    85: animation_default
    86: palette
    87: talk_color
    88: actor_name
    89: init_animation
    91: actor_width
    92: scale
    93: never_zclip
    94: always_zclip
    95: ignore_boxes
    96: follow_boxes
    97: animation_speed
    98: shadow
    99: text_offset
    100: load_script
    101: load_sound
    102: load_costume
    103: load_room
    104: nuke_script
    105: nuke_sound
    106: nuke_costume
    107: nuke_room
    108: lock_script
    109: lock_sound
    110: lock_costume
    111: lock_room
    112: unlock_script
    113: unlock_sound
    114: unlock_costume
    115: unlock_room
    116: clear_heap
    117: load_charset
    118: nuke_charset
    119: load_object
    124: verb_image
    125: verb_name
    126: verb_color
    127: verb_hicolor
    128: verb_at
    129: verb_on
    130: verb_off
    131: verb_delete
    132: verb_new
    133: verb_dimcolor
    134: verb_dim
    135: verb_key
    136: verb_center
    137: verb_name_str
    139: verb_image_in_room
    140: verb_bakcolor
    141: save_verbs
    142: restore_verbs
    143: delete_verbs
    144: cursor_on
    145: cursor_off
    146: userput_on
    147: userput_off
    148: cursor_soft_on
    149: cursor_soft_off
    150: userput_soft_on
    151: userput_soft_off
    153: cursor_image
    154: cursor_hotspot
    156: charset_set
    157: charset_color
    158: restart
    159: pause
    160: quit
    168: wait_for_actor
    169: wait_for_message
    170: wait_for_camera
    171: wait_for_sentence
    172: room_scroll
    174: room_screen
    175: room_palette
    176: room_shake_on
    177: room_shake_off
    179: room_intensity
    180: room_savegame
    181: room_fade
    182: rgb_room_intensity
    183: room_shadow
    184: save_string
    185: load_string
    186: room_transform
    187: cycle_speed
    196: verb_init
    197: set_current_actor
    198: actor_variable
    199: int_array
    200: bit_array
    201: nibble_array
    202: byte_array
    203: string_array
    204: undim_array
    205: assign_string
    208: assign_int_list
    212: assign_2dim_list
    213: room_new_palette
    214: cursor_transparent
    215: actor_ignore_turns_on
    216: actor_ignore_turns_off
    217: neww
    225: always_zclip_ft_demo
    226: wait_for_animation
    227: actor_depth
    228: actor_walk_script
    229: actor_stop
    230: actor_face
    231: actor_turn
    232: wait_for_turn
    233: actor_walk_pause
    234: actor_walk_resume
    235: actor_talk_script
    254: baseop
    255: endd

  # ScummEngine::readVar()
  # https://github.com/scummvm/scummvm/blob/master/engines/scumm/script.cpp#L533
  var_type:
    0x0: scumm_var  # _scummVar / var%d
    0x1: local      # vm.localvar / localvar%d
    0x2: bitvar     # _bitVars / bitvar%d
                    # NOTE: v8+ uses roomVars instead of bitvars

types:
  op:
    seq:
      - id: id
        type: u1
        enum: op_type
      - id: body
        type:
          switch-on: id
          cases:
            'op_type::push_byte': byte_data
            'op_type::push_word': word_data
            'op_type::push_byte_var': byte_data
            'op_type::push_word_var': word_var_data
            'op_type::byte_array_read': byte_array_read
            'op_type::word_array_read': word_array_read
            'op_type::byte_array_write': byte_array_write
            'op_type::word_array_write': word_array_write
            'op_type::byte_array_indexed_read': byte_array_indexed_read
            'op_type::byte_array_indexed_write': byte_array_indexed_write
            'op_type::word_array_indexed_read': word_array_indexed_read
            'op_type::word_array_indexed_write': word_array_indexed_write
            'op_type::dup': no_data
            'op_type::nott': no_data
            'op_type::eq': no_data
            'op_type::neq': no_data
            'op_type::gt': no_data
            'op_type::lt': no_data
            'op_type::le': no_data
            'op_type::ge': no_data
            'op_type::add': no_data
            'op_type::sub': no_data
            'op_type::mul': no_data
            'op_type::div': no_data
            'op_type::land': no_data
            'op_type::lor': no_data
            'op_type::pop1': call_func_pop1
            # 'op_type::write_byte_var': no_data
            'op_type::write_word_var': word_var_data
            # 'op_type::byte_array_inc': no_data
            # 'op_type::word_array_inc': no_data
            'op_type::byte_var_inc': byte_var_data
            'op_type::word_var_inc': word_var_data
            'op_type::byte_var_dec': byte_var_data
            'op_type::word_var_dec': word_var_data
            # 'op_type::byte_array_dec': no_data
            # 'op_type::word_array_dec': no_data
            'op_type::iff': jump_data
            'op_type::if_not': jump_data
            'op_type::start_script': start_script
            'op_type::start_script_quick': start_script_quick
            'op_type::start_object': start_object
            'op_type::draw_object': call_func_pop2
            'op_type::draw_object_at': call_func_pop3
            'op_type::draw_blast_object': draw_blast_object
            'op_type::set_blast_object_window': call_func_pop4
            'op_type::stop_object_code1': no_data
            'op_type::stop_object_code2': no_data
            'op_type::stop_object_script': call_func_pop1
            'op_type::end_cutscene': call_func_pop0
            'op_type::cutscene': call_func_list
            'op_type::stop_music': call_func_pop0
            'op_type::freeze_unfreeze': call_func_pop1
            'op_type::cursor_command': cursor_command
            'op_type::break_here': no_data
            'op_type::if_class_of_is': if_class_of_is
            'op_type::set_class': set_class
            'op_type::get_state': call_func_pop1_push
            'op_type::set_state': call_func_pop2
            'op_type::set_owner': call_func_pop2
            'op_type::get_owner': call_func_pop1_push
            'op_type::jump': jump_data
            'op_type::start_sound': call_func_pop1
            'op_type::stop_sound': call_func_pop1
            # 'op_type::start_music': no_data
            'op_type::pan_camera_to': call_func_pop1
            'op_type::actor_follow_camera': call_func_pop1
            'op_type::set_camera_at': call_func_pop1
            'op_type::load_room': call_func_pop1
            'op_type::load_room_with_ego': call_func_pop4
            'op_type::stop_script': call_func_pop1
            'op_type::walk_actor_to_obj': call_func_pop3
            'op_type::walk_actor_to': call_func_pop3
            'op_type::put_actor_at_xy': call_func_pop4
            'op_type::put_actor_at_object': call_func_pop3
            'op_type::face_actor': call_func_pop2
            'op_type::animate_actor': call_func_pop2
            'op_type::do_sentence': call_func_pop4
            'op_type::pickup_object': call_func_pop2
            'op_type::get_random_number': call_func_pop1_push
            'op_type::get_random_number_range': call_func_pop2_push
            'op_type::get_actor_moving': call_func_pop1_push
            'op_type::is_script_running': call_func_pop1_push
            'op_type::get_actor_room': call_func_pop1_push
            'op_type::get_object_x': call_func_pop1_push
            'op_type::get_object_y': call_func_pop1_push
            'op_type::get_object_old_dir': call_func_pop1_push
            'op_type::get_object_new_dir': call_func_pop1_push
            'op_type::get_actor_walk_box': call_func_pop1_push
            'op_type::get_actor_costume': call_func_pop1_push
            'op_type::find_inventory': call_func_pop2_push
            'op_type::get_inventory_count': call_func_pop1_push
            'op_type::get_verb_from_xy': call_func_pop2_push
            'op_type::get_verb_entrypoint': call_func_pop2_push
            'op_type::begin_override': begin_override
            'op_type::end_override': call_func_pop0
            'op_type::set_object_name': message
            'op_type::is_sound_running': call_func_pop1_push
            'op_type::set_box_flags': set_box_flags
            'op_type::create_box_matrix': call_func_pop0
            'op_type::resource_routines': resource_routines
            'op_type::room_ops': room_ops
            'op_type::actor_ops': actor_ops
            'op_type::verb_ops': verb_ops
            # 'op_type::get_actor_from_xy': no_data
            'op_type::find_object': call_func_pop2_push
            # 'op_type::pseudo_room': no_data
            # 'op_type::get_actor_elevation': no_data
            'op_type::array_ops': array_ops
            'op_type::save_restore_verbs': call_func_pop3_byte
            # 'op_type::draw_box': no_data
            'op_type::pop2': call_func_pop1
            'op_type::get_actor_width': call_func_pop1_push
            'op_type::wait': wait
            'op_type::get_actor_scale_x': call_func_pop1_push
            'op_type::get_actor_anim_counter': call_func_pop1_push
            'op_type::sound_kludge': call_func_list
            'op_type::is_any_of': is_any_of
            'op_type::system_ops': system_ops
            'op_type::is_actor_in_box': call_func_pop2_push
            'op_type::delay': call_func_pop1
            'op_type::delay_seconds': call_func_pop1
            'op_type::delay_minutes': call_func_pop1
            'op_type::stop_sentence': call_func_pop0
            'op_type::print_line': print
            'op_type::print_text': print
            'op_type::print_debug': print
            'op_type::print_system': print
            'op_type::print_actor': print
            # FIXME: has push(VAR_EGO)
            # 'op_type::print_ego': print

            # _actorToPrintStrFor = pop1()
            # then interpreter?
            'op_type::talk_actor': message
            # need to push(VAR_EGO)
            'op_type::talk_ego': message

            'op_type::dim_array': dim_array
            # 'op_type::dummy': no_data
            # 'op_type::start_object_quick': no_data
            # 'op_type::start_script_quick2': no_data
            # 'op_type::dim2dim_array': no_data
            'op_type::abs': call_func_pop1_push
            'op_type::dist_object_object': call_func_pop2_push
            'op_type::dist_object_pt': call_func_pop3_push
            'op_type::dist_pt_pt': call_func_pop4_push
            # 'op_type::kernel_get_functions': no_data
            # 'op_type::kernel_set_functions': no_data
            'op_type::delay_frames': call_func_pop1
            # 'op_type::pick_one_of': no_data
            # 'op_type::pick_one_of_default': no_data
            # 'op_type::stamp_object': no_data
            # 'op_type::get_date_time': no_data
            # 'op_type::stop_talking': no_data
            # 'op_type::get_animate_variable': no_data
            # 'op_type::shuffle': no_data
            # 'op_type::jump_to_script': no_data
            # 'op_type::band': no_data
            # 'op_type::bor': no_data
            # 'op_type::is_room_script_running': no_data
            # 'op_type::find_all_objects': no_data
            # 'op_type::get_pixel': no_data
            # 'op_type::pick_var_random': no_data
            # 'op_type::set_box_set': no_data
            # 'op_type::get_actor_layer': no_data
            _: unknown_op
    -webide-representation: '{id} {id:dec} {body}'

  # descumm-common.cpp: get_string()
  # https://github.com/scummvm/scummvm-tools/blob/master/engines/scumm/descumm-common.cpp#L264
  #
  # also ScummEngine::convertMessageToString() (doesn't parse commands directly)
  # https://github.com/scummvm/scummvm/blob/master/engines/scumm/string.cpp#L1379
  message:
    types:
      part:
        types:
          terminator:
            seq: []
          regular_char:
            seq: []
            params:
              - id: value
                type: u1
            -webide-representation: '{value:hex}'
          special_sequence:
            types:
              newline:
                seq: []
              keep_text:
                seq: []
              wait:
                seq: []
              int_message:
                seq:
                  - id: value
                    type: u2
              verb_message:
                seq:
                  - id: value
                    type: u2
              name_message:
                seq:
                  - id: value
                    type: u2
              string_message:
                seq:
                  - id: value
                    type: u2
              start_anim:
                seq:
                  - id: value
                    type: u2
              sound:
                instances:
                  value1:
                    value: (v2 << 16) | v1
                  value2:
                    value: (v4 << 16) | v3
                seq:
                  - id: v1
                    type: u2
                  - id: pad1
                    contents: [0xff, 0x0a]
                  - id: v2
                    type: u2
                  - id: pad2
                    contents: [0xff, 0x0a]
                  - id: v3
                    type: u2
                  - id: pad3
                    contents: [0xff, 0x0a]
                  - id: v4
                    type: u2
              set_color:
                seq:
                  - id: value
                    type: u2
              unknown13:
                seq:
                  - id: value
                    type: u2
              set_font:
                seq:
                  - id: value
                    type: u2
            seq:
              - id: code
                type: u1
              - id: payload
                type:
                  switch-on: code
                  cases:
                    1: newline
                    2: keep_text
                    3: wait
                    4: int_message
                    5: verb_message
                    6: name_message
                    7: string_message
                    9: start_anim
                    10: sound
                    12: set_color
                    13: unknown13
                    14: set_font
                    _: unknown_op
        seq:
          - id: data
            type: u1
          - id: content
            type:
              switch-on: data
              cases:
                0x00: terminator
                0xFF: special_sequence
                _: regular_char(data)
    seq:
      - id: parts
        type: part
        repeat: until
        repeat-until: _.data == 0x00

  no_data:
    seq:
      - id: data
        size: 0
    -webide-representation: '{data}'

  call_func_list:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  begin_override:
    seq:
      - id: call_func
        size: 0
      - id: arg1
        type: s1
      - id: arg2
        type: s2
    instances:
        pop_count:
          value: 0
    -webide-representation: '{data}'

  byte_array_read:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u1
    instances:
        pop_count:
          value: 1
        push_count:
          value: 1
    -webide-representation: '{data}'

  byte_array_write:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u1
    instances:
        pop_count:
          value: 2
        push_count:
          value: 1
    -webide-representation: '{data}'

  byte_array_indexed_read:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u1
    instances:
        pop_count:
          value: 2
        push_count:
          value: 1
    -webide-representation: '{data}'

  byte_array_indexed_write:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u1
    instances:
        pop_count:
          value: 3
        push_count:
          value: 1
    -webide-representation: '{data}'

  word_array_read:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u2
    instances:
        pop_count:
          value: 1
        push_count:
          value: 1
    -webide-representation: '{data}'

  word_array_write:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u2
    instances:
        pop_count:
          value: 2
        push_count:
          value: 1
    -webide-representation: '{data}'

  word_array_indexed_read:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u2
    instances:
        pop_count:
          value: 2
        push_count:
          value: 1
    -webide-representation: '{data}'

  word_array_indexed_write:
    seq:
      - id: call_func
        size: 0
      - id: array
        type: u2
    instances:
        pop_count:
          value: 3
        push_count:
          value: 1
    -webide-representation: '{data}'

  draw_blast_object:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 5
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  set_box_flags:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        pop_list:
          value: true
        pop_list_first:
          value: false
    -webide-representation: '{data}'

  set_class:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  is_any_of:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        pop_list:
          value: true
        pop_list_first:
          value: true
        push_count:
          value: 1
    -webide-representation: '{data}'

  if_class_of_is:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        pop_list:
          value: true
        pop_list_first:
          value: true
        push_count:
          value: 1
    -webide-representation: '{data}'

  start_object:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 3
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  start_script:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 2
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  start_script_quick:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        pop_list:
          value: true
        pop_list_first:
          value: true
    -webide-representation: '{data}'

  # for functions without params
  call_func_pop0:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 0
    -webide-representation: '{data}'

  call_func_pop1_word:
    seq:
      - id: call_func
        size: 0
      - id: param
        type: s2
    instances:
        pop_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop1_push:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
        push_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop2_push:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 2
        push_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop3_push:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 3
        push_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop4_push:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 4
        push_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop1:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 1
    -webide-representation: '{data}'

  call_func_pop2:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 2
    -webide-representation: '{data}'

  call_func_pop3:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 3
    -webide-representation: '{data}'

  call_func_pop3_byte:
    seq:
      - id: call_func
        size: 0
      - id: param
        type: u1
    instances:
        pop_count:
          value: 3
    -webide-representation: '{data}'

  call_func_pop4:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 4
    -webide-representation: '{data}'

  call_func_pop5:
    seq:
      - id: call_func
        size: 0
    instances:
        pop_count:
          value: 5
    -webide-representation: '{data}'

  call_func_string:
    seq:
      - id: data
        type: str
        encoding: ASCII
        terminator: 0
    -webide-representation: '{data}'

  byte_data:
    seq:
      - id: data
        type: s1
    -webide-representation: '{data}'

  word_data:
    seq:
      - id: data
        type: s2
    -webide-representation: '{data}'

  string_data:
    seq:
      - id: data
        type: str
        encoding: ISO-8859-1
        terminator: 0
    -webide-representation: '{data}'

  word7_data:
    seq:
      - id: data1
        type: s2
      - id: data2
        type: s2
      - id: data3
        type: s2
      - id: data4
        type: s2
      - id: data5
        type: s2
      - id: data6
        type: s2
      - id: data7
        type: s2
    -webide-representation: '{data}'

  byte_var_data:
    seq:
      - id: data
        type: u1
    instances:
      type:
        value: var_type::scumm_var
    -webide-representation: '(i:{data:dec} {type})'

  word_var_data:
    seq:
      - id: data
        type: b14
      - id: type
        type: b2
        enum: var_type
    -webide-representation: '(i:{data:dec} {type})'

  jump_data:
    seq:
      - id: jump_offset
        type: s2
    -webide-representation: '{jump_offset}'

  verb_ops:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::verb_init': call_func_pop1
            'subop_type::verb_image': call_func_pop1
            # FIXME: probably wrong?
            'subop_type::verb_name': message
            'subop_type::verb_color': call_func_pop1
            'subop_type::verb_hicolor': call_func_pop1
            'subop_type::verb_at': call_func_pop2
            'subop_type::verb_on': call_func_pop0
            'subop_type::verb_off': call_func_pop0
            'subop_type::verb_delete': call_func_pop1
            'subop_type::verb_new': call_func_pop0
            'subop_type::verb_dimcolor': call_func_pop1
            'subop_type::verb_dim': call_func_pop0
            'subop_type::verb_key': call_func_pop1
            'subop_type::verb_center': call_func_pop0
            # 'subop_type::verb_name_str': no_data
            'subop_type::verb_image_in_room': call_func_pop2
            'subop_type::verb_bakcolor': call_func_pop1
            'subop_type::endd': call_func_pop0
            _: unknown_op
    -webide-representation: '{subop}'

  resource_routines:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::load_charset': call_func_pop1
            'subop_type::nuke_charset': call_func_pop1
            'subop_type::load_script': call_func_pop1
            'subop_type::load_sound': call_func_pop1
            'subop_type::load_costume': call_func_pop1
            'subop_type::load_room': call_func_pop1
            'subop_type::load_object': call_func_pop2
            # 'subop_type::load_string': no_data
            'subop_type::nuke_script': call_func_pop1
            'subop_type::nuke_sound': call_func_pop1
            'subop_type::nuke_costume': call_func_pop1
            'subop_type::nuke_room': call_func_pop1
            'subop_type::lock_script': call_func_pop1
            'subop_type::lock_sound': call_func_pop1
            'subop_type::lock_costume': call_func_pop1
            'subop_type::lock_room': call_func_pop1
            'subop_type::unlock_script': call_func_pop1
            'subop_type::unlock_sound': call_func_pop1
            'subop_type::unlock_costume': call_func_pop1
            'subop_type::unlock_room': call_func_pop1
            _: unknown_op
    -webide-representation: '{subop}'

  cursor_command:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::charset_set': call_func_pop1
            'subop_type::charset_color': call_func_list
            'subop_type::cursor_on': call_func_pop0
            'subop_type::cursor_off': call_func_pop0
            'subop_type::cursor_soft_on': call_func_pop0
            'subop_type::cursor_soft_off': call_func_pop0
            'subop_type::cursor_image': call_func_pop2
            'subop_type::cursor_hotspot': call_func_pop2
            'subop_type::cursor_transparent': call_func_pop1
            'subop_type::userput_on': call_func_pop0
            'subop_type::userput_off': call_func_pop0
            'subop_type::userput_soft_on': call_func_pop0
            'subop_type::userput_soft_off': call_func_pop0
            _: unknown_op
    -webide-representation: '{subop}'

  room_ops:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::room_scroll': call_func_pop2
            'subop_type::room_screen': call_func_pop2
            'subop_type::room_palette': call_func_pop4
            'subop_type::room_shake_on': call_func_pop0
            'subop_type::room_shake_off': call_func_pop0
            'subop_type::room_intensity': call_func_pop3
            'subop_type::room_savegame': call_func_pop2
            'subop_type::room_fade': call_func_pop1
            'subop_type::rgb_room_intensity': call_func_pop5
            'subop_type::room_shadow': call_func_pop5
            'subop_type::room_transform': call_func_pop4
            'subop_type::room_new_palette': call_func_pop1
            _: unknown_op
    -webide-representation: '{subop}'

  actor_ops:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::set_costume': call_func_pop1
            'subop_type::step_dist': call_func_pop2
            # 'subop_type::sound': no_data
            'subop_type::walk_animation': call_func_pop1
            'subop_type::talk_animation': call_func_pop2
            'subop_type::stand_animation': call_func_pop1
            # 'subop_type::animation': no_data
            'subop_type::init': call_func_pop0
            'subop_type::elevation': call_func_pop1
            # 'subop_type::animation_default': no_data
            'subop_type::palette': call_func_pop2
            'subop_type::talk_color': call_func_pop1
            'subop_type::actor_name': call_func_string
            'subop_type::init_animation': call_func_pop1
            'subop_type::actor_width': call_func_pop1
            'subop_type::scale': call_func_pop1
            'subop_type::never_zclip': call_func_pop0
            'subop_type::always_zclip': call_func_pop1
            'subop_type::always_zclip_ft_demo': call_func_pop1
            'subop_type::ignore_boxes': call_func_pop0
            'subop_type::follow_boxes': call_func_pop0
            'subop_type::animation_speed': call_func_pop1
            # 'subop_type::shadow': no_data
            'subop_type::text_offset': call_func_pop2
            # 'subop_type::clear_heap': no_data
            # 'subop_type::save_verbs': no_data
            # 'subop_type::restore_verbs': no_data
            # 'subop_type::delete_verbs': no_data
            # 'subop_type::save_string': no_data
            # 'subop_type::cycle_speed': no_data
            'subop_type::set_current_actor': call_func_pop1 # SPECIAL CASE! Sets current actor!
            # 'subop_type::actor_variable': no_data
            # 'subop_type::actor_ignore_turns_on': no_data
            # 'subop_type::actor_ignore_turns_off': no_data
            # 'subop_type::neww': no_data
            # 'subop_type::wait_for_animation': no_data
            # 'subop_type::actor_depth': no_data
            # 'subop_type::actor_walk_script': no_data
            # 'subop_type::actor_stop': no_data
            # 'subop_type::actor_face': no_data
            # 'subop_type::actor_turn': no_data
            # 'subop_type::wait_for_turn': no_data
            # 'subop_type::actor_walk_pause': no_data
            # 'subop_type::actor_walk_resume': no_data
            # 'subop_type::actor_talk_script': no_data
            # 'subop_type::baseop': no_data
            _: unknown_op
    -webide-representation: '{subop}'

  wait:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::wait_for_actor': call_func_pop1_word
            'subop_type::wait_for_message': call_func_pop0
            'subop_type::wait_for_camera': call_func_pop0
            # 'subop_type::wait_for_sentence': no_data
            # 'subop_type::wait_for_animation': no_data
            # 'subop_type::wait_for_turn': no_data
            _: unknown_op
    -webide-representation: '{subop}'

  print:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::at': call_func_pop2
            'subop_type::color': call_func_pop1
            'subop_type::clipped': call_func_pop1
            'subop_type::center': call_func_pop0
            'subop_type::left': call_func_pop0
            'subop_type::overhead': call_func_pop0
            'subop_type::textstring': message
            'subop_type::mumble': call_func_pop0
            'subop_type::baseop': no_data
            'subop_type::endd': call_func_pop0
            _: unknown_op
    -webide-representation: '{subop}'

  system_ops:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::restart': call_func_pop0
            'subop_type::pause': call_func_pop0
            'subop_type::quit': call_func_pop0
            _: unknown_op
    -webide-representation: '{subop}'

  array_ops:
    seq:
      - id: array
        type: u2
      - id: subop
        type: u1
        enum: subop_type
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::assign_string': message
            # 'subop_type::assign_int_list': no_data
            # 'subop_type::assign_2dim_list': no_data
            _: unknown_op
    -webide-representation: '{subop}'

  dim_array:
    seq:
      - id: subop
        type: u1
        enum: subop_type
      - id: array
        type: u2
      - id: body
        type:
          switch-on: subop
          cases:
            'subop_type::int_array': call_func_pop1
            'subop_type::bit_array': call_func_pop1
            'subop_type::nibble_array': call_func_pop1
            'subop_type::byte_array': call_func_pop1
            'subop_type::string_array': call_func_pop1
            'subop_type::undim_array': call_func_pop1_word
            _: unknown_op
    -webide-representation: '{subop}'

  unknown_op:
    seq:
      - id: data
        size-eos: true
