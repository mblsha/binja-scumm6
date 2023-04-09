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
    # 00
    0x00: push_byte
    0x01: push_word
    0x02: push_byte_var
    0x03: push_word_var
    # 04
    0x06: byte_array_read
    0x07: word_array_read
    # 10
    0x10: gt
    0x11: lt
    0x12: le
    0x13: ge
    # 14
    0x14: add
    0x15: sub
    0x16: mul
    0x17: div
    # 1C
    # 20
    # 24
    # 28
    # 2C
    # 30
    # 34
    # 38
    # 3C
    # 40
    0x43: write_word_var
    # 54
    0x56: byte_var_dec
    0x57: word_var_dec
    # 5C
    0x5c: if
    0x5d: if_not
    0x5e: start_script
    0x5f: start_script_quick
    # 64
    0x64: set_blast_object_window
    0x65: stop_object_code1
    0x66: stop_object_code2
    0x67: end_cutscene
    # 6C
    0x6c: break_here
    0x6d: if_class_of_is
    0x6e: set_class
    0x6f: get_state
    # 70
    0x70: set_state
    0x71: set_owner
    0x72: get_owner
    0x73: jump
    # AC
    0xac: sound_kludge
    0xad: is_any_of
    0xae: system_ops
    0xaf: is_actor_in_box
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

            'op_type::gt': no_data
            'op_type::lt': no_data
            'op_type::le': no_data
            'op_type::ge': no_data

            'op_type::add': no_data
            'op_type::sub': no_data
            'op_type::mul': no_data
            'op_type::div': no_data

            'op_type::write_word_var': word_data
            'op_type::word_var_dec': word_data

            'op_type::if': word_data
            'op_type::if_not': word_data

            'op_type::break_here': no_data
            'op_type::jump': word_data
            'op_type::stop_object_code1': no_data
            'op_type::stop_object_code2': no_data

            'op_type::sound_kludge': no_data

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
