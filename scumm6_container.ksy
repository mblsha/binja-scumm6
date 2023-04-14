meta:
  id: scumm6_container
  title: SCUMM6
  application: SCUMM Engine
  endian: le
  bit-endian: le # used for bit-fields

seq:
  - id: blocks
    type: block
    repeat: eos

enums:
  block_type:
    # Index blocks
    0x524e414d: rnam
    0x4d415853: maxs
    0x44534352: dscr
    0x44524f4f: droo
    0x44534f55: dsou
    0x44434f53: dcos
    0x44434852: dchr
    0x444f424a: dobj
    0x41415259: aary

    # Main blocks
    0x4c454346: lecf
    0x4c4f4646: loff
    0x4c464c46: lflf
    0x524f4f4d: room
    0x524d4844: rmhd
    0x4359434c: cycl
    0x54524e53: trns
    0x50414c53: pals
    0x57524150: wrap
    0x4f464653: offs
    0x4150414c: apal
    0x524d494d: rmim
    0x524d4948: rmih
    0x494d3030: im00
    0x534d4150: smap
    0x5a506e6e: zpnn
    0x4f42494d: obim
    0x494d4844: imhd
    0x494d6e6e: imnn
    0x4f424344: obcd
    0x43444844: cdhd
    0x56455242: verb
    0x4f424e41: obna
    0x45584344: excd
    0x454e4344: encd
    0x4e4c5343: nlsc
    0x4c534352: lscr
    0x424f5844: boxd
    0x424f584d: boxm
    0x5343414c: scal
    0x53435250: scrp
    0x534f554e: soun
    0x4d494449: midi
    0x534f55: sou
    0x524f4c: rol
    0x41444c: adl
    0x474d44: gmd
    0x434f5354: cost
    0x43484152: char

types:
  block:
    seq:
      - id: block_type
        type: u4be
        enum: block_type
      - id: block_size
        type: u4be
      - id: block_data
        size: block_size - 8
        type:
          switch-on: block_type
          cases:
            # Index blocks .000
            'block_type::rnam': rnam
            'block_type::maxs': maxs
            'block_type::dscr': index_no_offset
            'block_type::droo': index_no_offset
            'block_type::dsou': index_no_offset
            'block_type::dcos': index_no_offset
            'block_type::dchr': index_no_offset
            'block_type::dobj': dobj
            'block_type::aary': aary

            # Main blocks .001
            'block_type::lecf': nested_blocks
            'block_type::loff': loff
            'block_type::lflf': nested_blocks

            'block_type::room': nested_blocks
            'block_type::rmhd': rmhd
            # cycl
            'block_type::trns': trns

            'block_type::pals': nested_blocks
            'block_type::wrap': nested_blocks
            'block_type::offs': offs
            'block_type::apal': apal

            'block_type::rmim': nested_blocks
            'block_type::rmih': rmih
            'block_type::im00': nested_blocks

            'block_type::obim': nested_blocks
            'block_type::imhd': imhd
            'block_type::obcd': nested_blocks
            'block_type::cdhd': cdhd
            'block_type::obna': obna
            'block_type::nlsc': nlsc
            'block_type::boxd': boxd
            'block_type::boxm': boxm

            'block_type::encd': script
            'block_type::excd': script
            'block_type::lscr': local_script
            'block_type::scrp': script
            'block_type::verb': verb_script

            # 'block_type::soun': nested_blocks
            _: unknown_block
    -webide-representation: '{block_type} {block_size:dec}'

  # Main blocks
  nested_blocks:
    seq:
      - id: blocks
        type: block
        repeat: eos

  loff:
    types:
      room:
        seq:
          - id: room_id
            type: u1
          - id: room_offset
            type: u4le
    seq:
      - id: num_rooms
        type: u1
      - id: rooms
        type: room
        repeat: expr
        repeat-expr: num_rooms

  rmhd:
    seq:
      - id: width
        type: u2
      - id: height
        type: u2
      - id: num_objects
        type: u2
    -webide-representation: 'w:{width:dec} h:{height:dec} num_obj:{num_objects:dec}'

  rmih:
    seq:
      - id: num_z_buf
        type: u2
    -webide-representation: '{num_z_buf}'

  trns:
    seq:
      - id: transparent_color
        type: u1
    -webide-representation: '{transparent_color}'

  offs:
    seq:
      - id: offset
        type: u4
    -webide-representation: '{offset}'

  apal:
    types:
      pal:
        seq:
          - id: r
            type: u1
          - id: g
            type: u1
          - id: b
            type: u1
        -webide-representation: 'r:{r} g:{g} b:{b}'
    seq:
      - id: pal
        type: pal
        repeat: expr
        repeat-expr: 256

  imhd:
    types:
      hotspot:
        seq:
          - id: x
            type: s2
          - id: y
            type: s2
        -webide-representation: 'x:{x:dec} y:{y:dec}'
    seq:
      - id: obj_id
        type: u2
      - id: num_imnn
        type: u2
      - id: num_zpnn
        type: u2
      - id: unknown
        type: u2
      - id: x
        type: u2
      - id: y
        type: u2
      - id: w
        type: u2
      - id: h
        type: u2
      - id: num_hotspots
        type: u2
      - id: hotspots
        type: hotspot
        repeat: expr
        repeat-expr: num_hotspots

  cdhd:
    seq:
      - id: obj_id
        type: u2
      # upper-left corner
      - id: x
        type: u2
      - id: y
        type: u2
      - id: w
        type: u2
      - id: h
        type: u2
      - id: flags
        type: u1
      - id: parent
        type: u1
      - id: unknown1
        type: u2
      - id: unknown2
        type: u2
      - id: actor_dir
        type: u1

  verb_script:
    seq:
      - id: entry
        type: u1
        repeat: until
        repeat-until: _ == 0x00

  obna:
    seq:
      - id: name
        type: str
        encoding: ASCII
        terminator: 0
    -webide-representation: '{name}'

  nlsc:
    seq:
      - id: number_local_scripts
        type: u1
    -webide-representation: '{number_local_scripts}'

  boxd:
    types:
      box:
        seq:
          - id: ulx
            type: s2
          - id: uly
            type: s2
          - id: urx
            type: s2
          - id: ury
            type: s2
          - id: lrx
            type: s2
          - id: lry
            type: s2
          - id: llx
            type: s2
          - id: lly
            type: s2
          - id: mask
            type: u1
          # 0x08 : X flip
          # 0x10 : Y flip
          # 0x20 : Ignore scale / Player only
          # 0x40 : Locked
          # 0x80 : Invisible
          - id: flags
            type: u1
          - id: scale
            type: u2
    seq:
      - id: num_boxes
        type: u2
      - id: boxes
        type: box
        repeat: expr
        repeat-expr: num_boxes

  boxm:
    seq:
      # FIXME
      - id: v1
        type: u1

  script:
    seq:
      - id: data
        size-eos: true

  local_script:
    seq:
      - id: index
        type: u1
      - id: data
        size-eos: true





  # Index blocks
  rnam:
    types:
      resource_name:
        seq:
          - id: resource_id
            type: u1
          - id: name
            type: str
            encoding: ASCII
            terminator: 0
            if: resource_id != 0x00
        -webide-representation: '{resource_id} name:{name}'
    seq:
      - id: resource_names
        type: resource_name
        repeat: until
        repeat-until: _.resource_id == 0x00

  # List of pre-allocated arrays,
  # these will be allocated by the engine before running the boot script
  aary:
    types:
      element:
        seq:
          - id: var_no
            type: u2
          - id: xsize
            type: u2
            if: var_no != 0
          - id: ysize
            type: u2
            if: var_no != 0
          - id: type
            type: u2
            if: var_no != 0

    seq:
      - id: elements
        type: element
        repeat: until
        repeat-until: _.var_no == 0x00

  # FIXME: verify labels are correct
  maxs:
    seq:
      - id: num_variables
        type: u2
      - id: num_bit_variables
        type: u2
      - id: num_local_objects
        type: u2
      - id: num_global_objects
        type: u2
      - id: num_verbs
        type: u2
      - id: num_fl_object_slots
        type: u2
      - id: num_arrays
        type: u2
      - id: num_rooms
        type: u2
      - id: num_scripts
        type: u2
      - id: num_sounds
        type: u2
      - id: num_costumes
        type: u2
      - id: num_charsets
        type: u2
      - id: num_images
        type: u2

  index_no_offset:
    seq:
      - id: num_entries
        type: u2
      - id: index_no
        type: u1
        repeat: expr
        repeat-expr: num_entries
      - id: room_offset
        type: u4le
        repeat: expr
        repeat-expr: num_entries

  dobj:
    types:
      owner_state:
        seq:
          # FIXME: is order correct?
          - id: owner
            type: b4
          - id: state
            type: b4
        -webide-representation: 'o:{owner} s:{state}'
    seq:
      - id: num_entries
        type: u2
      - id: owner_state
        type: owner_state
        repeat: expr
        repeat-expr: num_entries
      - id: class_data
        type: u4le
        repeat: expr
        repeat-expr: num_entries

  unknown_block:
    seq:
      - id: data
        size-eos: true
