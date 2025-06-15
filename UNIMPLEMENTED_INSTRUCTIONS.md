# SCUMM6 Instruction Migration Status

This document tracks the migration of SCUMM6 instructions from the monolithic `scumm6.py` implementation to the new object-oriented instruction architecture in `src/pyscumm6/`.

## ✅ Migrated Instructions

| Opcode | Name | Class | Status |
|--------|------|-------|--------|
| 0 | `push_byte` | `PushByte` | ✅ Complete |
| 1 | `push_word` | `PushWord` | ✅ Complete |
| 2 | `push_byte_var` | `PushByteVar` | ✅ Complete |
| 3 | `push_word_var` | `PushWordVar` | ✅ Complete |
| 12 | `dup` | `Dup` | ✅ Complete |
| 26 | `pop1` | `Pop1` | ✅ Complete |
| 167 | `pop2` | `Pop2` | ✅ Complete |

## 🔄 Priority Instructions for Migration

These instructions have full LLIL implementations and should be migrated first:

### Stack Operations
- [x] `push_word` (1) - Push word constant
- [x] `push_byte_var` (2) - Push byte variable
- [x] `push_word_var` (3) - Push word variable
- [x] `dup` (12) - Duplicate top stack item
- [x] `pop1` (26) - Pop single item
- [x] `pop2` (167) - Pop single item (despite the name)

### Arithmetic Operations
- [ ] `add` (20) - Addition
- [ ] `sub` (21) - Subtraction
- [ ] `mul` (22) - Multiplication
- [ ] `div` (23) - Division
- [ ] `abs` (196) - Absolute value

### Logical Operations
- [ ] `land` (24) - Logical AND
- [ ] `lor` (25) - Logical OR
- [ ] `nott` (13) - Logical NOT
- [ ] `band` (214) - Bitwise AND
- [ ] `bor` (215) - Bitwise OR

### Comparison Operations
- [ ] `eq` (14) - Equal
- [ ] `neq` (15) - Not equal
- [ ] `gt` (16) - Greater than
- [ ] `lt` (17) - Less than
- [ ] `le` (18) - Less than or equal
- [ ] `ge` (19) - Greater than or equal

### Variable Operations
- [ ] `write_byte_var` (66) - Write byte to variable
- [ ] `write_word_var` (67) - Write word to variable
- [ ] `byte_var_inc` (78) - Increment byte variable
- [ ] `word_var_inc` (79) - Increment word variable
- [ ] `byte_var_dec` (86) - Decrement byte variable
- [ ] `word_var_dec` (87) - Decrement word variable

### Array Operations
- [ ] `byte_array_read` (6) - Read from byte array
- [ ] `word_array_read` (7) - Read from word array
- [ ] `byte_array_indexed_read` (10) - Indexed byte array read
- [ ] `word_array_indexed_read` (11) - Indexed word array read
- [ ] `byte_array_write` (70) - Write to byte array
- [ ] `word_array_write` (71) - Write to word array
- [ ] `byte_array_indexed_write` (74) - Indexed byte array write
- [ ] `word_array_indexed_write` (75) - Indexed word array write
- [ ] `byte_array_inc` (82) - Increment byte array element
- [ ] `word_array_inc` (83) - Increment word array element
- [ ] `byte_array_dec` (90) - Decrement byte array element
- [ ] `word_array_dec` (91) - Decrement word array element

### Control Flow
- [ ] `iff` (92) - If true (conditional branch)
- [ ] `if_not` (93) - If false (conditional branch)
- [ ] `jump` (115) - Unconditional jump
- [ ] `jump_to_script` (213) - Jump to script

### Script Operations
- [ ] `start_script` (94) - Start script with flags
- [ ] `start_script_quick` (95) - Start script without flags
- [ ] `start_script_quick2` (191) - Start script quick variant 2
- [ ] `stop_script` (124) - Stop script
- [ ] `is_script_running` (139) - Check if script is running
- [ ] `is_room_script_running` (216) - Check if room script is running

### Object Operations
- [ ] `start_object` (96) - Start object
- [ ] `start_object_quick` (190) - Start object quick
- [ ] `stop_object_code1` (101) - Stop object code (variant 1)
- [ ] `stop_object_code2` (102) - Stop object code (variant 2)
- [ ] `stop_object_script` (119) - Stop object script

### Utility
- [ ] `break_here` (108) - Breakpoint/debug instruction

## 🏗️ Complex Instructions (Intrinsic Candidates)

These instructions have complex implementations with sub-operations and may be better handled as intrinsics:

### Game Engine Operations
- [ ] `draw_object` (97) - Draw object
- [ ] `draw_object_at` (98) - Draw object at position
- [ ] `draw_blast_object` (99) - Draw blast object
- [ ] `set_blast_object_window` (100) - Set blast object window
- [ ] `stamp_object` (205) - Stamp object

### Cutscene Operations
- [ ] `cutscene` (104) - Start cutscene
- [ ] `end_cutscene` (103) - End cutscene

### Audio Operations
- [ ] `start_sound` (116) - Start sound
- [ ] `stop_sound` (117) - Stop sound
- [ ] `start_music` (118) - Start music
- [ ] `stop_music` (105) - Stop music
- [ ] `is_sound_running` (152) - Check if sound is running
- [ ] `sound_kludge` (172) - Sound system hack
- [ ] `stop_talking` (209) - Stop talking

### Camera Operations
- [ ] `pan_camera_to` (120) - Pan camera to position
- [ ] `actor_follow_camera` (121) - Actor follow camera
- [ ] `set_camera_at` (122) - Set camera at position

### Room Operations
- [ ] `load_room` (123) - Load room
- [ ] `load_room_with_ego` (133) - Load room with ego
- [ ] `pseudo_room` (161) - Pseudo room operation
- [ ] `room_ops` (156) - Room operations (complex)

### Actor Operations
- [ ] `walk_actor_to_obj` (125) - Walk actor to object
- [ ] `walk_actor_to` (126) - Walk actor to position
- [ ] `put_actor_at_xy` (127) - Put actor at coordinates
- [ ] `put_actor_at_object` (128) - Put actor at object
- [ ] `face_actor` (129) - Face actor
- [ ] `animate_actor` (130) - Animate actor
- [ ] `get_actor_moving` (138) - Get actor moving state
- [ ] `get_actor_room` (140) - Get actor room
- [ ] `get_actor_walk_box` (144) - Get actor walk box
- [ ] `get_actor_costume` (145) - Get actor costume
- [ ] `get_actor_from_xy` (159) - Get actor from coordinates
- [ ] `get_actor_elevation` (162) - Get actor elevation
- [ ] `get_actor_width` (168) - Get actor width
- [ ] `get_actor_scale_x` (170) - Get actor scale X
- [ ] `get_actor_anim_counter` (171) - Get actor animation counter
- [ ] `is_actor_in_box` (175) - Check if actor in box
- [ ] `get_actor_layer` (236) - Get actor layer
- [ ] `actor_ops` (157) - Actor operations (complex)

### Object Query Operations
- [ ] `get_object_x` (141) - Get object X position
- [ ] `get_object_y` (142) - Get object Y position
- [ ] `get_object_old_dir` (143) - Get object old direction
- [ ] `get_object_new_dir` (237) - Get object new direction
- [ ] `find_object` (160) - Find object
- [ ] `find_all_objects` (221) - Find all objects

### Inventory Operations
- [ ] `pickup_object` (132) - Pick up object
- [ ] `find_inventory` (146) - Find inventory item
- [ ] `get_inventory_count` (147) - Get inventory count

### Verb Operations
- [ ] `do_sentence` (131) - Do sentence
- [ ] `get_verb_from_xy` (148) - Get verb from coordinates
- [ ] `get_verb_entrypoint` (163) - Get verb entrypoint
- [ ] `verb_ops` (158) - Verb operations (complex)
- [ ] `save_restore_verbs` (165) - Save/restore verbs

### Text/Dialog Operations
- [ ] `print_line` (180) - Print line
- [ ] `print_text` (181) - Print text
- [ ] `print_debug` (182) - Print debug
- [ ] `print_system` (183) - Print system message
- [ ] `print_actor` (184) - Print actor dialog
- [ ] `print_ego` (185) - Print ego dialog
- [ ] `talk_actor` (186) - Talk actor
- [ ] `talk_ego` (187) - Talk ego
- [ ] `stop_sentence` (179) - Stop sentence

### System Operations
- [ ] `freeze_unfreeze` (106) - Freeze/unfreeze
- [ ] `cursor_command` (107) - Cursor command
- [ ] `if_class_of_is` (109) - If class of is
- [ ] `set_class` (110) - Set class
- [ ] `get_state` (111) - Get state
- [ ] `set_state` (112) - Set state
- [ ] `set_owner` (113) - Set owner
- [ ] `get_owner` (114) - Get owner
- [ ] `begin_override` (149) - Begin override
- [ ] `end_override` (150) - End override
- [ ] `set_object_name` (151) - Set object name
- [ ] `set_box_flags` (153) - Set box flags
- [ ] `create_box_matrix` (154) - Create box matrix
- [ ] `draw_box` (166) - Draw box
- [ ] `system_ops` (174) - System operations (complex)
- [ ] `set_box_set` (228) - Set box set

### Resource Operations
- [ ] `resource_routines` (155) - Resource routines (complex)

### Array Management
- [ ] `dim_array` (188) - Dimension array
- [ ] `dim2dim_array` (192) - 2D dimension array
- [ ] `array_ops` (164) - Array operations (complex)

### Timing Operations
- [ ] `wait` (169) - Wait
- [ ] `delay` (176) - Delay
- [ ] `delay_seconds` (177) - Delay seconds
- [ ] `delay_minutes` (178) - Delay minutes
- [ ] `delay_frames` (202) - Delay frames

### Random/Math Operations
- [ ] `get_random_number` (135) - Get random number
- [ ] `get_random_number_range` (136) - Get random number in range
- [ ] `pick_one_of` (203) - Pick one of
- [ ] `pick_one_of_default` (204) - Pick one of with default
- [ ] `pick_var_random` (227) - Pick variable random
- [ ] `shuffle` (212) - Shuffle

### Distance/Geometry Operations
- [ ] `dist_object_object` (197) - Distance object to object
- [ ] `dist_object_pt` (198) - Distance object to point
- [ ] `dist_pt_pt` (199) - Distance point to point
- [ ] `get_pixel` (225) - Get pixel

### Special Operations
- [ ] `is_any_of` (173) - Is any of
- [ ] `get_date_time` (208) - Get date/time
- [ ] `get_animate_variable` (210) - Get animate variable
- [ ] `kernel_get_functions` (200) - Kernel get functions
- [ ] `kernel_set_functions` (201) - Kernel set functions
- [ ] `dummy` (189) - Dummy/no-op instruction

## Migration Guidelines

### Step-by-Step Migration Process:

1. **Find the instruction implementation in `scumm6.py`**
   - Search for the opcode in `get_instruction_low_level_il()` method
   - Note how it handles the LLIL generation
   - Check if it's handled as an intrinsic or has special logic

2. **Create the instruction class in `src/pyscumm6/instr/instructions.py`**
   ```python
   class InstructionName(Instruction):

       def render(self) -> List[Token]:
           # Extract value from self.op_details.body
           value = self.op_details.body.data
           return [
               TInstr("instruction_name"),
               TSep("("),
               TInt(str(value)),  # or other token types as needed
               TSep(")"),
           ]

       def lift(self, il: LowLevelILFunction, addr: int) -> None:
           # Add type assertion for the Kaitai struct
           assert isinstance(self.op_details.body, Scumm6Opcodes.ExpectedType), \
               f"Expected ExpectedType body, got {type(self.op_details.body)}"

           # Copy LLIL logic from scumm6.py
           value = self.op_details.body.data
           il.append(...)  # Your LLIL implementation
   ```

3. **Determine the correct Kaitai type**
   - Check `scumm6_opcodes.py` for the body type
   - Common types: `ByteData`, `WordData`, `ByteVarData`, `WordVarData`, `NoData`
   - Can test with: `python -c "from src.scumm6_opcodes import Scumm6Opcodes; print(dir(Scumm6Opcodes))"`

4. **Add to opcode mapping in `src/pyscumm6/instr/opcode_table.py`**
   ```python
   OPCODE_MAP: Dict[Scumm6Opcodes.OpType, Type[Instruction]] = {
       # ... existing mappings ...
       Scumm6Opcodes.OpType.instruction_name: instructions.InstructionName,
   }
   ```

5. **Add test case in `src/test_instruction_migration.py`**
   ```python
   @pytest.mark.parametrize("opcode_name, opcode_bytes", [
       # ... existing tests ...
       ("instruction_name", b"\xXX\xYY\xZZ"),  # Add comment explaining the bytes
   ])
   ```

6. **Run the test**
   ```bash
   FORCE_BINJA_MOCK=1 python -m pytest src/test_instruction_migration.py -v
   ```

7. **Update this tracking document**
   - Move instruction from "Priority Instructions" to "Migrated Instructions"
   - Update migration counts
   - Mark with [x] in the priority list

### For Simple Instructions:
Instructions that just push/pop values or perform basic operations on the stack.

### For Complex Instructions:
Instructions with sub-operations (like `array_ops`, `actor_ops`) may need:
- Additional parsing of sub-operation codes
- Multiple render formats based on sub-op
- Consider implementing as intrinsics with proper typing

## Notes

- Instructions are ordered by implementation complexity and frequency of use
- Priority should be given to core computational instructions first
- Game-specific operations may be better handled as typed intrinsics
- Each migrated instruction should have corresponding tests validating LLIL consistency
