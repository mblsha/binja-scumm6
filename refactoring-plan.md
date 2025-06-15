This document outlines a comprehensive plan to implement the remaining SCUMM6 instructions parsed by Kaitai Struct within the `pyscumm6` architecture. The plan emphasizes creating a generic, maintainable, and extensible system by refactoring existing code and grouping new instructions logically.

### 1. Executive Summary

The goal is to complete the migration from the monolithic `scumm6.py` lifter to the new object-oriented instruction system in `src/pyscumm6/`. This will be achieved by:

1.  **Identifying and Grouping** all remaining instructions based on their function (e.g., Variable/Array, Control Flow, Engine Intrinsics).
2.  **Refactoring for Genericity** by creating abstract base classes for common instruction patterns (e.g., binary stack operations, variable access, array access).
3.  **Implementing Remaining Instructions** by subclassing these generic base classes, drastically reducing boilerplate code.
4.  **Handling Complex Operations** as typed `intrinsics` to keep the Low-Level IL (LLIL) clean and readable.

This approach will not only accelerate the implementation of the remaining ~100 instructions but also ensure the final architecture is robust, easy to test, and simple to extend.

### 2. Remaining Instructions and Grouping Strategy

Based on `UNIMPLEMENTED_INSTRUCTIONS.md`, the remaining instructions can be categorized as follows.

#### ✅ Group 1: Variable and Array Operations (COMPLETED)
These instructions read from or write to the game's state variables and dynamically sized arrays. They are a high priority as they are fundamental to game logic.

*   **✅ Variable Writes:** `write_byte_var` (66), `write_word_var` (67)
*   **✅ Array Reads:** `byte_array_read` (6), `word_array_read` (7), `byte_array_indexed_read` (10), `word_array_indexed_read` (11)
*   **✅ Array Writes:** `byte_array_write` (70), `word_array_write` (71), `byte_array_indexed_write` (74), `word_array_indexed_write` (75)
*   **✅ Array Increments/Decrements:** `byte_array_inc` (82), `word_array_inc` (83), `byte_array_dec` (90), `word_array_dec` (91)
*   **🚧 Array Dimensioning:** `dim_array` (188), `dim2dim_array` (192), `array_ops` (164) - Deferred to Group 3

#### ✅ Group 2: Control Flow (COMPLETED)
These instructions alter the flow of execution, either within a script or by jumping to another script. They are critical for building an accurate Control-Flow Graph (CFG).

*   **✅ Conditional Jumps:** `iff` (92), `if_not` (93)
*   **✅ Unconditional Jumps:** `jump` (115)
*   **🚧 Script Jumps:** `jump_to_script` (213) - Deferred to Group 3
*   **🚧 Script/Object Execution:** `start_script` (94), `start_script_quick` (95), `start_script_quick2` (191), `start_object` (96), `start_object_quick` (190) - Deferred to Group 3
*   **🚧 Script/Object Termination:** `stop_script` (124), `stop_object_code1` (101), `stop_object_code2` (102), `stop_object_script` (119) - Deferred to Group 3

#### 🚧 Group 3: Complex Engine Intrinsics (SIGNIFICANT PROGRESS)
This is the largest group, consisting of high-level engine functions. These are best implemented as `intrinsic` calls in LLIL. They can be subgrouped by functionality.

*   **✅ Actor Query Operations:** `face_actor` ✅, `animate_actor` ✅, `get_actor_moving` ✅, `get_actor_room` ✅, `get_actor_costume` ✅, `get_actor_walk_box` ✅, `get_actor_from_xy` ✅, `get_actor_elevation` ✅, `get_actor_width` ✅, `get_actor_scale_x` ✅, `get_actor_anim_counter` ✅, `is_actor_in_box` ✅, `get_actor_layer` ✅
*   **✅ Actor Movement Operations:** `walk_actor_to_obj` ✅, `walk_actor_to` ✅, `put_actor_at_xy` ✅, `put_actor_at_object` ✅
*   **Actor Complex Operations:** `actor_ops`, etc.
*   **✅ Object & Drawing Operations:** `draw_object` ✅, `draw_object_at` ✅, `draw_blast_object` ✅, `stop_object_code1` ✅, `stop_object_code2` ✅, `stop_object_script` ✅
*   **✅ Object Query Operations:** `get_object_x` ✅, `get_object_y` ✅, `get_object_old_dir` ✅, `pickup_object` ✅
*   **✅ Audio Operations:** `start_sound` ✅, `stop_sound` ✅, `stop_music` ✅, `is_sound_running` ✅
*   **✅ Script Operations:** `is_script_running` ✅
*   **Dialog & Text Operations:** `print_*`, `talk_actor`, `talk_ego`, `stop_sentence` ✅, `stop_talking` ✅, etc.
*   **✅ Inventory Operations:** `find_inventory` ✅, `get_inventory_count` ✅
*   **✅ Verb Operations:** `do_sentence` ✅, `get_verb_from_xy` ✅
*   **✅ Room & Camera Operations:** `load_room` ✅, `pan_camera_to` ✅, `set_camera_at` ✅, `actor_follow_camera` ✅
*   **✅ System & State Operations:** `end_cutscene` ✅, `get_state` ✅, `set_state` ✅, `set_owner` ✅, `get_owner` ✅, `freeze_unfreeze` ✅, `begin_override` ✅, `end_override` ✅, `set_object_name` ✅, `set_box_flags` ✅, `create_box_matrix` ✅
*   **✅ Timing Operations:** `wait` ✅, `delay` ✅, `delay_seconds` ✅, `delay_minutes` ✅, `delay_frames` ✅
*   **✅ Additional Script Operations:** `start_music` ✅, `stop_script` ✅, `is_room_script_running` ✅
*   **✅ Additional Object Operations:** `get_object_new_dir` ✅, `find_object` ✅
*   **✅ Distance/Geometry Operations:** `dist_object_object` ✅, `dist_object_pt` ✅, `dist_pt_pt` ✅, `get_pixel` ✅
*   **✅ Utility Operations:** `get_date_time` ✅, `get_animate_variable` ✅, `pick_var_random` ✅
*   **✅ Additional Verb Operations:** `get_verb_entrypoint` ✅

### 3. Plan for Generic Implementation and Refactoring

Before implementing new instructions, we will refactor the existing instruction set to use generic base classes. This establishes a clean pattern for all future work.

#### 3.1. Refactor Existing Stack Operations

Many arithmetic and logical instructions follow the same pattern: pop one or two values, perform an operation, and push the result.

**Action:** Create `_UnaryStackOp` and `_BinaryStackOp` abstract base classes.

```python
# In a new file: src/pyscumm6/instr/helpers.py or similar
from abc import abstractmethod
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP, ExpressionIndex

class _UnaryStackOp(Instruction):
    @abstractmethod
    def _get_llil_op(self, il: LowLevelILFunction, val: ExpressionIndex) -> ExpressionIndex:
        pass

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        val = il.pop(4)
        result = self._get_llil_op(il, val)
        il.append(il.push(4, result))

class _BinaryStackOp(Instruction):
    @abstractmethod
    def _get_llil_op(self, il: LowLevelILFunction, left: ExpressionIndex, right: ExpressionIndex) -> ExpressionIndex:
        pass

    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        right = il.pop(4) # Right-hand side operand is popped first
        left = il.pop(4)
        result = self._get_llil_op(il, left, right)
        il.append(il.push(4, result))
```

**Example Refactoring:** The `Add` instruction becomes trivial.

```python
# In src/pyscumm6/instr/instructions.py
from .helpers import _BinaryStackOp

class Add(_BinaryStackOp):
    def render(self) -> List[Token]:
        return [TInstr("add")]

    def _get_llil_op(self, il: LowLevelILFunction, left: ExpressionIndex, right: ExpressionIndex) -> ExpressionIndex:
        return il.add(4, left, right)
```

This pattern will be applied to `Sub`, `Mul`, `Div`, `Eq`, `Neq`, `Gt`, `Lt`, `Le`, `Ge`, `Land`, `Lor`, and `Nott`.

#### 3.2. Create Generic Variable and Array Operation Handlers

These operations access memory representing game state. We can create base classes that use the helpers in `src/vars.py`.

**Action:** Create `_VariableOp` and `_ArrayOp` base classes.

**Variable Operations:**
```python
# In src/pyscumm6/instr/helpers.py
from ... import vars
from ...scumm6_opcodes import Scumm6Opcodes

class _VariableWriteOp(Instruction):
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Assumes the body is a WordVarData or ByteVarData Kaitai object
        value = il.pop(4)
        il.append(vars.il_set_var(il, self.op_details.body, value))
```
**Example Usage:**
```python
# In src/pyscumm6/instr/instructions.py
class WriteWordVar(_VariableWriteOp):
    def render(self) -> List[Token]:
        # ... render logic ...
        return [TInstr("write_word_var"), TSep("("), TInt(f"var_{self.op_details.body.data}"), TSep(")")]
```

**Array Operations:**
This is more complex and will be a significant improvement. A helper can manage popping indices and calculating the array element address.

```python
# In src/pyscumm6/instr/helpers.py
def _lift_array_op(
    instr: Instruction, il: LowLevelILFunction, pop_count: int, is_write: bool, is_modify: bool = False
) -> None:
    body = instr.op_details.body
    array_id = body.array

    # Pop indices and value (if writing) from the stack
    popped_values = [il.pop(4) for _ in range(pop_count)]

    # Use temporary registers to hold popped values
    for i, val in enumerate(popped_values):
        il.append(il.set_reg(4, LLIL_TEMP(i), val))

    # Construct arguments for vars.il_get/set_array
    # Note: array operations have a different stack order than intrinsics
    base = il.reg(4, LLIL_TEMP(0))
    index = il.reg(4, LLIL_TEMP(1)) if pop_count > 1 else il.const(4, 0)
    value_to_write = il.reg(4, LLIL_TEMP(2)) if pop_count > 2 else base

    if is_write:
        if is_modify: # For inc/dec
            current_value = vars.il_get_array(il, array_id, index, base)
            # is_modify would need to pass in the operation (add/sub)
            modified_value = il.add(4, current_value, il.const(4, 1)) # example for inc
            il.append(vars.il_set_array(il, array_id, index, base, modified_value))
        else: # Regular write
            il.append(vars.il_set_array(il, array_id, index, base, value_to_write))
    else: # Read
        result = vars.il_get_array(il, array_id, index, base)
        il.append(il.push(4, result))
```

### 4. Step-by-Step Implementation Plan

Follow this refined workflow for each new instruction group.

1.  **Select a Group:** Start with Group 1 (Variables/Arrays).
2.  **Create Generic Helper/Base Class:** Implement the generic base class (`_VariableWriteOp`, `_ArrayOp`, `_ControlFlowOp`, `_IntrinsicOp`) as designed above.
3.  **Implement an Instruction:**
    a.  Create the instruction class in `src/pyscumm6/instr/instructions.py`, inheriting from the appropriate base class.
    b.  Implement the `render()` method to provide disassembly text.
    c.  Implement the `lift()` method (or a helper like `_get_llil_op()`) using the logic from `scumm6.py` and the new generic structure. Add the Kaitai type assertion.
4.  **Register the Instruction:** Add the new class to `OPCODE_MAP` in `src/pyscumm6/instr/opcode_table.py`.
5.  **Add a Test Case:** Add a test case to `src/test_instruction_migration.py` using a known byte sequence for the opcode.
6.  **Run Tests:** Use `./run-tests.fish --once` to run all checks (ruff, mypy, pytest) and ensure consistency with the old implementation and no regressions.
7.  **Update Tracking Document:** Mark the instruction as complete in `UNIMPLEMENTED_INSTRUCTIONS.md`.

#### Detailed Plan for Group 1: Variable and Array Operations

*   **`write_byte_var`, `write_word_var`:** Implement using the `_VariableWriteOp` base class. The `lift` method is inherited; only `render` is needed.
*   **Array Read/Write/Inc/Dec:** Create a generic `_ArrayOp(Instruction)` base class. Subclasses like `ByteArrayRead`, `WordIndexedWrite`, etc., will call a shared `_lift_array_op` helper, passing parameters to specify pop count and operation type (read/write/modify). This is a significant refactoring that will handle all 12 array instructions with minimal repeated code.

#### Detailed Plan for Group 2: Control Flow

*   **`iff`, `if_not`:** These will require a custom `lift` method that pops a value and uses `il.if_expr`. They must also implement the `analyze()` method to call `info.add_branch` for both the `TrueBranch` (the jump target) and `FalseBranch` (the next instruction), which is essential for the CFG.
*   **`jump`:** Similar to the above, but unconditional. Implements `lift` with `il.jump` and `analyze` with `BranchType.UnconditionalBranch`.
*   **`start_script`, `stop_script`, etc.:** These are context-dependent and will use the global `State` object. The `lift` method will:
    1.  Pop the script ID from the stack.
    2.  Use a helper `LastBV.get().state` to access the global state.
    3.  Call `Scumm6Disasm.get_script_ptr(state, script_id, addr)` to resolve the ID to a function address.
    4.  Generate an `il.call` to the resolved address. This correctly builds the CFG.
    5.  The `analyze` method must do the same resolution to provide the `CallDestination` to Binary Ninja.

#### Detailed Plan for Group 3: Complex Engine Intrinsics

*   **Action:** Create a generic `_IntrinsicOp` base class. This class's `lift` method will be parameterized by the number of arguments to pop from the stack and whether a result is pushed. The Kaitai-parsed body (`CallFuncPop1`, `CallFuncPop2Push`, etc.) provides this information directly.

```python
# In src/pyscumm6/instr/helpers.py
class _IntrinsicOp(Instruction):
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Determine pop/push counts from Kaitai type name
        op_body_type = type(self.op_details.body).__name__
        pop_count = 0
        push_count = 0

        # Example logic, can be refined
        if 'Pop1' in op_body_type: pop_count = 1
        if 'Pop2' in op_body_type: pop_count = 2
        # ... and so on for Pop3, Pop4

        if 'Push' in op_body_type: push_count = 1

        # Pop arguments from the stack
        args = [il.pop(4) for _ in range(pop_count)]

        # Get the intrinsic name (e.g., 'draw_object')
        intrinsic_name = self.op_details.id.name

        if push_count:
            il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, args))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        else:
            il.append(il.intrinsic([], intrinsic_name, args))
```

*   **Implementation:** All instructions in Group 3 will subclass `_IntrinsicOp`. Their `lift` method will be inherited entirely. Only `render()` will be needed. For intrinsics with sub-operations (like `actor_ops`), `render` will inspect `self.op_details.body.subop` to create a more descriptive name (e.g., `actor_ops.set_costume`). For text/dialog operations like `talk_actor`, a special `lift` method will be needed to resolve the string address from the global state, similar to how `start_script` resolves script addresses.

By following this plan, all remaining instructions can be implemented systematically, leveraging generic patterns to minimize code duplication and maximize maintainability.
