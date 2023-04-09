meta:
  id: scumm6_opcodes
  file-extension: scumm6_opcodes
  endian: le
  bit-endian: le # used for bit-fields

seq:
  - id: ops
    type: op
    repeat: eos

enums:
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
    0x0d: not
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
    0x5c: if
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

types:
  op:
    seq:
      - id: op_type
        type: u1
        enum: op_type
      - id: op_data
        type:
          switch-on: op_type
          cases:
            'op_type::push_byte': byte_data
            'op_type::push_word': word_data
            'op_type::push_byte_var': byte_data
            'op_type::push_word_var': word_data
            # 'op_type::byte_array_read': no_data
            # 'op_type::word_array_read': no_data
            # 'op_type::byte_array_indexed_read': no_data
            # 'op_type::word_array_indexed_read': no_data
            # 'op_type::dup': no_data
            # 'op_type::not': no_data
            # 'op_type::eq': no_data
            # 'op_type::neq': no_data
            'op_type::gt': no_data
            'op_type::lt': no_data
            'op_type::le': no_data
            'op_type::ge': no_data
            'op_type::add': no_data
            'op_type::sub': no_data
            'op_type::mul': no_data
            'op_type::div': no_data
            # 'op_type::land': no_data
            # 'op_type::lor': no_data
            # 'op_type::pop1': no_data
            # 'op_type::write_byte_var': no_data
            'op_type::write_word_var': word_data
            # 'op_type::byte_array_write': no_data
            # 'op_type::word_array_write': no_data
            # 'op_type::byte_array_indexed_write': no_data
            # 'op_type::word_array_indexed_write': no_data
            # 'op_type::byte_var_inc': no_data
            # 'op_type::word_var_inc': no_data
            # 'op_type::byte_array_inc': no_data
            # 'op_type::word_array_inc': no_data
            # 'op_type::byte_var_dec': no_data
            'op_type::word_var_dec': word_data
            # 'op_type::byte_array_dec': no_data
            # 'op_type::word_array_dec': no_data
            'op_type::if': word_data
            'op_type::if_not': word_data
            # 'op_type::start_script': no_data
            # 'op_type::start_script_quick': no_data
            # 'op_type::start_object': no_data
            # 'op_type::draw_object': no_data
            # 'op_type::draw_object_at': no_data
            # 'op_type::draw_blast_object': no_data
            # 'op_type::set_blast_object_window': no_data
            'op_type::stop_object_code1': no_data
            'op_type::stop_object_code2': no_data
            # 'op_type::end_cutscene': no_data
            # 'op_type::cutscene': no_data
            # 'op_type::stop_music': no_data
            # 'op_type::freeze_unfreeze': no_data
            # 'op_type::cursor_command': no_data
            'op_type::break_here': no_data
            # 'op_type::if_class_of_is': no_data
            # 'op_type::set_class': no_data
            # 'op_type::get_state': no_data
            # 'op_type::set_state': no_data
            # 'op_type::set_owner': no_data
            # 'op_type::get_owner': no_data
            'op_type::jump': word_data
            # 'op_type::start_sound': no_data
            # 'op_type::stop_sound': no_data
            # 'op_type::start_music': no_data
            # 'op_type::stop_object_script': no_data
            # 'op_type::pan_camera_to': no_data
            # 'op_type::actor_follow_camera': no_data
            # 'op_type::set_camera_at': no_data
            # 'op_type::load_room': no_data
            # 'op_type::stop_script': no_data
            # 'op_type::walk_actor_to_obj': no_data
            # 'op_type::walk_actor_to': no_data
            # 'op_type::put_actor_at_xy': no_data
            # 'op_type::put_actor_at_object': no_data
            # 'op_type::face_actor': no_data
            # 'op_type::animate_actor': no_data
            # 'op_type::do_sentence': no_data
            # 'op_type::pickup_object': no_data
            # 'op_type::load_room_with_ego': no_data
            # 'op_type::get_random_number': no_data
            # 'op_type::get_random_number_range': no_data
            # 'op_type::get_actor_moving': no_data
            # 'op_type::is_script_running': no_data
            # 'op_type::get_actor_room': no_data
            # 'op_type::get_object_x': no_data
            # 'op_type::get_object_y': no_data
            # 'op_type::get_object_old_dir': no_data
            # 'op_type::get_actor_walk_box': no_data
            # 'op_type::get_actor_costume': no_data
            # 'op_type::find_inventory': no_data
            # 'op_type::get_inventory_count': no_data
            # 'op_type::get_verb_from_xy': no_data
            # 'op_type::begin_override': no_data
            # 'op_type::end_override': no_data
            # 'op_type::set_object_name': no_data
            # 'op_type::is_sound_running': no_data
            # 'op_type::set_box_flags': no_data
            # 'op_type::create_box_matrix': no_data
            # 'op_type::resource_routines': no_data
            # 'op_type::room_ops': no_data
            # 'op_type::actor_ops': no_data
            # 'op_type::verb_ops': no_data
            # 'op_type::get_actor_from_xy': no_data
            # 'op_type::find_object': no_data
            # 'op_type::pseudo_room': no_data
            # 'op_type::get_actor_elevation': no_data
            # 'op_type::get_verb_entrypoint': no_data
            # 'op_type::array_ops': no_data
            # 'op_type::save_restore_verbs': no_data
            # 'op_type::draw_box': no_data
            # 'op_type::pop2': no_data
            # 'op_type::get_actor_width': no_data
            # 'op_type::wait': no_data
            # 'op_type::get_actor_scale_x': no_data
            # 'op_type::get_actor_anim_counter': no_data
            'op_type::sound_kludge': no_data
            # 'op_type::is_any_of': no_data
            # 'op_type::system_ops': no_data
            # 'op_type::is_actor_in_box': no_data
            # 'op_type::delay': no_data
            # 'op_type::delay_seconds': no_data
            # 'op_type::delay_minutes': no_data
            # 'op_type::stop_sentence': no_data
            # 'op_type::print_line': no_data
            # 'op_type::print_text': no_data
            # 'op_type::print_debug': no_data
            # 'op_type::print_system': no_data
            # 'op_type::print_actor': no_data
            # 'op_type::print_ego': no_data
            # 'op_type::talk_actor': no_data
            # 'op_type::talk_ego': no_data
            # 'op_type::dim_array': no_data
            # 'op_type::dummy': no_data
            # 'op_type::start_object_quick': no_data
            # 'op_type::start_script_quick2': no_data
            # 'op_type::dim2dim_array': no_data
            # 'op_type::abs': no_data
            # 'op_type::dist_object_object': no_data
            # 'op_type::dist_object_pt': no_data
            # 'op_type::dist_pt_pt': no_data
            # 'op_type::kernel_get_functions': no_data
            # 'op_type::kernel_set_functions': no_data
            # 'op_type::delay_frames': no_data
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
            # 'op_type::get_object_new_dir': no_data
            _: unknown_op
    -webide-representation: '{op_type} {op_data}'

  no_data:
    seq:
      - id: data
        size: 0
    -webide-representation: '{data}'

  byte_data:
    seq:
      - id: data
        type: u1
    -webide-representation: '{data}'

  word_data:
    seq:
      - id: data
        type: u2
    -webide-representation: '{data}'

  unknown_op:
    seq:
      - id: data
        size-eos: true
