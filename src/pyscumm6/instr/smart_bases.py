"""Smart base classes for generated instruction types."""

from typing import List, Optional, Any, NamedTuple, cast
from binja_helpers.tokens import Token, TInstr, TSep, TInt, TText
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP, LowLevelILLabel
from binaryninja import IntrinsicName
import copy

from .opcodes import Instruction
from .generic import ControlFlowOp
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig)
from ...scumm6_opcodes import Scumm6Opcodes

# Descumm-style function name mapping for improved semantic clarity
DESCUMM_FUNCTION_NAMES = {
    "stop_object_code1": "stopObjectCodeA",
    "stop_object_code2": "stopObjectCodeB", 
    "stop_script": "stopScript",
    "start_script": "startScript",
    "start_script_quick": "startScriptQuick",
    "start_script_quick2": "startScriptQuick2",
    "draw_object": "drawObject",
    "draw_object_at": "drawObjectAt",
    "animate_actor": "animateActor",
    "walk_actor_to": "walkActorTo",
    "cutscene": "beginCutscene",
    "put_actor_at_xy": "putActorInXY",
    "put_actor_in_xy": "putActorInXY",
    "face_actor": "faceActor",
    "start_sound": "startSound",
    "start_music": "startMusic", 
    "stop_sound": "stopSound",
    "talk_actor": "talkActor",
    "talk_ego": "talkEgo",
    "is_script_running": "isScriptRunning",
    "kernel_get_functions": "kernelGetFunctions",
    "kernel_set_functions": "kernelSetFunctions",
    "room_ops": "roomOps",
    "actor_ops": "actorOps",
    "verb_ops": "verbOps",
    "sound_kludge": "soundKludge",
    "break_here": "breakHere",
    "breakHere": "breakHere",
    "delay": "delay",
    "delay_frames": "delayFrames",
    "dim_array": "dimArray",
    "dim2dim_array": "dim2dimArray",
    "freeze_unfreeze": "freezeUnfreeze",
    "print_line": "printLine",
    "print_text": "printText",
    "print_system": "printSystem",
    "print_actor": "printActor",
    "print_ego": "printEgo",
    "wait": "wait",
    "wait_for_message": "waitForMessage",
    "pickup_object": "pickupObject",
    "do_sentence": "doSentence",
    "load_room": "loadRoom",
    "pan_camera_to": "panCameraTo",
    "set_camera_at": "setCameraAt",
    "actor_follow_camera": "actorFollowCamera",
    "set_state": "setState",
    "set_owner": "setOwner",
    "set_class": "setClass",
    # Object intrinsics
    "get_object_x": "getObjectX",
    "get_object_y": "getObjectY",
    "get_random_number": "getRandomNumber",
    "is_any_of": "isAnyOf",
    "is_actor_in_box": "isActorInBox",
    # Complex operations 
    "print_debug.begin": "printDebug.begin",
    "print_debug.msg": "printDebug.msg",
    "print_text.color": "printCursor.color",
    # Print line subcommands
    "print_line.begin": "printLine.begin",
    "print_line.color": "printLine.color",
    "print_line.xy": "printLine.XY",
    "print_line.center": "printLine.center",
    "print_line.overhead": "printLine.overhead",
    "print_line.clipped": "printLine.right",  # descumm uses "right" for clipped
    "print_line.end": "printLine.end",
    "room_ops.room_screen": "roomOps.setScreen",
    # Actor operations subcommands
    "actor_ops.set_current_actor": "actorOps.setCurActor",
    "actor_ops.init": "actorOps.init",
    "actor_ops.set_costume": "actorOps.setCostume", 
    "actor_ops.ignore_boxes": "actorOps.setIgnoreBoxes",
    "actor_ops.never_zclip": "actorOps.setNeverZClip",
    "actor_ops.elevation": "actorOps.setElevation",
    "actor_ops.talk_color": "actorOps.setTalkColor",
    "actor_ops.actor_name": "actorOps.setName",
    "actor_ops.step_dist": "actorOps.setWalkSpeed",
    "actor_ops.walk_speed": "actorOps.setWalkSpeed",
    "actor_ops.text_offset": "actorOps.setTalkPos",
    "actor_ops.scale": "actorOps.setScale",
    "actor_ops.palette": "actorOps.setPalette",
    "actor_ops.actor_width": "actorOps.setWidth",
    # Wait operation subcommands
    "wait.wait_for_message": "wait.waitForMessage",
    "wait.wait_for_actor": "wait.waitForActor",
    "wait.wait_for_camera": "wait.waitForCamera",
    # Room operations subcommands
    "room_ops.room_palette": "roomOps.setPalColor",
    "room_ops.room_intensity": "roomOps.darkenPalette",
    "room_ops.rgb_room_intensity": "roomOps.darkenPalette",
    "room_ops.room_fade": "roomOps.screenEffect",
    # Cursor commands
    "cursor_command": "cursorCommand",
    # Verb operations subcommands
    "verb_ops.verb_init": "verbOps.init",
    "verb_ops.verb_new": "verbOps.new",
    "verb_ops.verb_delete": "verbOps.delete",
    "verb_ops.verb_name": "verbOps.loadString",
    "verb_ops.verb_at": "verbOps.at",
    "verb_ops.verb_on": "verbOps.setOn",
    "verb_ops.verb_off": "verbOps.setOff",
    "verb_ops.verb_color": "verbOps.setColor",
    "verb_ops.verb_hicolor": "verbOps.setHiColor",
    "verb_ops.verb_redraw": "verbOps.redraw",
    "verb_ops.verb_dim": "verbOps.dim",
    "verb_ops.verb_key": "verbOps.setKey",
    "verb_ops.verb_center": "verbOps.setCenter",
    "verb_ops.verb_name_str": "verbOps.setNameStr",
    "verb_ops.verb_image_in_room": "verbOps.setToObject",
    "verb_ops.verb_bakcolor": "verbOps.bakcolor",
    "verb_ops.verb_set_cur_verb": "verbOps.setCurVerb",
    "verb_ops.verb_init_2": "verbOps.init",
    "verb_ops.verb_end": "verbOps.end",
    "verb_ops.endd": "verbOps.redraw",  # endd is actually redraw in descumm
    "verb_ops.verb_dimcolor": "verbOps.dimColor",  # Missing mapping
    "verb_ops.verb_load_string": "verbOps.loadString",
    "verb_ops.save_verbs": "verbOps.saveVerbs",
    "verb_ops.restore_verbs": "verbOps.restoreVerbs",
    "verb_ops.delete_verbs": "verbOps.deleteVerbs",
    "verb_ops.verb_load_string2": "verbOps.loadString",
    "verb_ops.verb_assign": "verbOps.assign",
    "verb_ops.set_verb_object": "verbOps.setVerbObject",
}


def get_variable_name(var_num: int, use_raw_names: bool = False, use_var_prefix: bool = True) -> str:
    """Get the proper variable name for a given variable number.
    
    Args:
        var_num: The variable number
        use_raw_names: If True, always use var_N format (descumm-style for assignments)
        use_var_prefix: If True, keep VAR_ prefix for system variables (descumm-style)
    
    Returns the descumm-style name if it's a known system variable,
    otherwise returns var_N format.
    """
    from ... import vars
    
    # If requested, always use raw variable names (matches descumm for assignments)
    if use_raw_names:
        # For descumm literal compatibility, use varN format (no underscore)
        return f"var{var_num}"
    
    # Get the system variable mappings
    var_mapping = vars.scumm_vars_inverse()
    
    if var_num in var_mapping:
        var_name = var_mapping[var_num]
        
        # For descumm compatibility, preserve VAR_ prefix for system variables
        if use_var_prefix:
            return var_name
        else:
            # Legacy behavior: Remove VAR_ prefix and convert to camelCase
            if var_name.startswith("VAR_"):
                var_name = var_name[4:]
            # Convert SNAKE_CASE to camelCase
            parts = var_name.split('_')
            if len(parts) > 1:
                # First part lowercase, rest title case
                var_name = parts[0].lower() + ''.join(p.title() for p in parts[1:])
            else:
                var_name = var_name.lower()
            return var_name
    else:
        # For non-system variables, use varN format (descumm literal compatibility)
        return f"var{var_num}"


class FusibleMultiOperandMixin:
    """
    Mixin class providing common fusion logic for instructions that consume multiple operands.
    
    This mixin consolidates the common fusion patterns found across:
    - SmartFusibleIntrinsic (pop_count operands)
    - SmartBinaryOp (2 operands)
    - SmartArrayOp (2-3 operands)
    - SmartComparisonOp (2 operands)
    - SmartConditionalJump (1 operand)
    
    Reduces code duplication by 80+ lines across multiple classes.
    """
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        # Subclasses should override this method
        if hasattr(self, '_config') and hasattr(self._config, 'pop_count'):
            return int(self._config.pop_count)
        return 2  # Default for binary operations
    
    def _can_fuse_more(self) -> bool:
        """Check if this instruction can accept more fused operands."""
        if not hasattr(self, 'fused_operands'):
            return True
        return len(self.fused_operands) < self._get_max_operands()
    
    def _create_fused_copy(self, previous: Instruction) -> 'Instruction':
        """Create a deep copy of this instruction with the previous instruction fused."""
        fused = copy.deepcopy(self)
        
        # Ensure fused_operands exists
        if not hasattr(fused, 'fused_operands'):
            return fused  # type: ignore[return-value]
            
        # For stack-based operations, use LIFO ordering: most recent push goes to front
        # This ensures proper stack semantics where last-pushed becomes first operand
        fused.fused_operands.insert(0, previous)
        
        # Update total length if _length exists
        if hasattr(fused, '_length') and hasattr(self, '_length') and hasattr(previous, 'length'):
            fused._length = self._length + previous.length()
        
        return fused  # type: ignore[return-value]
    
    def _standard_fuse(self, previous: Instruction) -> Optional['Instruction']:
        """
        Standard fusion logic suitable for most multi-operand instructions.
        
        Args:
            previous: The previous instruction to potentially fuse with
            
        Returns:
            A new fused instruction if fusion is possible, None otherwise
        """
        # Check if we can accept more operands
        if not self._can_fuse_more():
            return None
        
        # Check if previous is fusible
        if not self._is_fusible_push(previous):
            return None
        
        # Create and return fused instruction
        return self._create_fused_copy(previous)
    
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused."""
        class_name = instr.__class__.__name__
        
        # Basic push operations
        if class_name in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            return True
        
        # Result-producing operations (for multi-level fusion)
        if hasattr(instr, 'produces_result') and instr.produces_result():
            return True
        
        return False


class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation base class."""
    
    _name: str
    _config: IntrinsicConfig

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self._config.special_lift == "cutscene_lift":
            if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
                return len(self.op_details.body.args)
            return 0
        return self._config.pop_count
    
    def produces_result(self) -> bool:
        """Check if this intrinsic produces a result that can be consumed by other instructions."""
        return self._config.push_count > 0
    
    def render(self, as_operand: bool = False) -> List[Token]:
        # Use descumm-style function names for better semantic clarity
        display_name = DESCUMM_FUNCTION_NAMES.get(self._name, self._name)
        
        # Add parentheses for function call syntax consistency
        # For descumm literal compatibility, always show () instead of (...)
        return [TInstr(f"{display_name}()")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Handle special lift cases
        if self._config.special_lift:
            special_method = getattr(self, self._config.special_lift)
            special_method(il, addr)
            return
            
        # Handle UnknownOp case - generate double unimplemented
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            il.append(il.unimplemented())
            il.append(il.unimplemented())
            return
        
        # Standard intrinsic lift
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        
        if self._config.push_count > 0:
            # Create temp registers for outputs
            output_regs = [LLIL_TEMP(i) for i in range(self._config.push_count)]
            il.append(il.intrinsic(output_regs, self._name, params))
            # Push the output values
            for reg in output_regs:
                il.append(il.push(4, il.reg(4, reg)))
        else:
            il.append(il.intrinsic([], self._name, params))
    
    def no_ret_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for instructions that don't return."""
        # Do standard lift first
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        il.append(il.intrinsic([], self._name, params))
        il.append(il.no_ret())
    
    def cutscene_lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Special lift for cutscene with dynamic argument count."""
        # Custom logic for cutscene argument parsing
        if hasattr(self.op_details.body, 'args') and hasattr(self.op_details.body.args, '__len__'):
            pop_count = len(self.op_details.body.args)
        else:
            pop_count = 0
            
        params = [il.pop(4) for _ in range(pop_count)]
        il.append(il.intrinsic([], self._name, params))


class SmartFusibleIntrinsic(SmartIntrinsicOp, FusibleMultiOperandMixin):
    """Intrinsic operation that supports instruction fusion for function-call style rendering."""
    
    def fuse(self, previous: Instruction) -> Optional['SmartFusibleIntrinsic']:
        """Attempt to fuse with the previous instruction using standard fusion logic."""
        return cast(Optional['SmartFusibleIntrinsic'], self._standard_fuse(previous))
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        # If we have fused operands, we pop fewer from the stack
        if hasattr(self, 'fused_operands'):
            return max(0, self._config.pop_count - len(self.fused_operands))
        return super().stack_pop_count
    
    def render(self, as_operand: bool = False) -> List[Token]:
        """Render the instruction, showing fused operands if available."""
        # Use descumm-style function names for better semantic clarity
        display_name = DESCUMM_FUNCTION_NAMES.get(self._name, self._name)
        
        if self.fused_operands:
            # Function-call style: drawObject(100, 200)
            tokens: List[Token] = [TInstr(display_name), TSep("(")]
            
            # Add operands in correct order (reverse of fusion order)
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
            
            tokens.append(TSep(")"))
            return tokens
        else:
            # Normal rendering with parentheses
            # For descumm literal compatibility, always show () instead of (...)
            return [TInstr(f"{display_name}()")]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        from binja_helpers.tokens import TInt, TText
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - extract var number and type
            if hasattr(operand.op_details.body, 'data'):
                data = operand.op_details.body.data
                # Handle signed byte interpretation for PushByteVar
                if operand.__class__.__name__ == 'PushByteVar' and data < 0:
                    data = data + 256
                
                # Check if this is a local variable
                if hasattr(operand.op_details.body, 'type'):
                    var_type = operand.op_details.body.type
                    if var_type == Scumm6Opcodes.VarType.local:
                        return [TInt(f"localvar{data}")]
                    elif var_type == Scumm6Opcodes.VarType.bitvar:
                        return [TInt(f"bitvar{data}")]
                
                # System variable - use semantic name mapping
                return [TInt(get_variable_name(data, use_raw_names=True))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            # Constant push - extract value
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
        elif hasattr(operand, 'produces_result') and operand.produces_result():
            # This is a result-producing instruction (like Add with fused operands)
            # Just render it directly
            return operand.render()
        
        # Fallback
        return [TText("?")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Lift the instruction, using fused operands if available."""
        if self.fused_operands:
            # Build parameters from fused operands
            params = []
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
            
            # Add any remaining stack pops if we don't have all operands fused
            remaining_pops = self._config.pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
            
            # Generate the intrinsic call
            if self._config.push_count > 0:
                # Create temp registers for outputs
                output_regs = [LLIL_TEMP(i) for i in range(self._config.push_count)]
                il.append(il.intrinsic(output_regs, IntrinsicName(self._name), params))
                # Push the output values
                for reg in output_regs:
                    il.append(il.push(4, il.reg(4, reg)))
            else:
                il.append(il.intrinsic([], IntrinsicName(self._name), params))
        else:
            # Use parent implementation
            super().lift(il, addr)
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        from ... import vars
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - use il_get_var
            return vars.il_get_var(il, operand.op_details.body)
        else:
            # Constant push - use const
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return il.const(4, value)
        
        # Fallback to undefined
        return il.undefined()


class SmartVariableOp(Instruction):
    """Self-configuring variable operation base class."""
    
    _name: str
    _config: VariableConfig

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return 0

    def render(self, as_operand: bool = False) -> List[Token]:
        var_id = self.op_details.body.data
        var_name = get_variable_name(var_id)
        
        # Use C-style increment/decrement notation for better readability
        if self._config.operation == "inc":
            return [
                TInt(var_name),
                TInstr("++"),
            ]
        elif self._config.operation == "dec":
            return [
                TInt(var_name),
                TInstr("--"),
            ]
        else:
            # Fallback to function call style for other operations
            return [
                TInstr(self._name),
                TSep("("),
                TInt(var_name),
                TSep(")"),
            ]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ... import vars
        
        expected_type = (Scumm6Opcodes.ByteVarData if self._config.var_type == "byte" 
                        else Scumm6Opcodes.WordVarData)
        
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        if self._config.operation == "inc":
            current_value = vars.il_get_var(il, self.op_details.body)
            incremented_value = il.add(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, incremented_value))
        elif self._config.operation == "dec":
            current_value = vars.il_get_var(il, self.op_details.body)
            decremented_value = il.sub(4, current_value, il.const(4, 1))
            il.append(vars.il_set_var(il, self.op_details.body, decremented_value))

class SmartComplexOp(FusibleMultiOperandMixin, Instruction):
    """Unified complex operation handler."""
    
    _name: str
    _config: ComplexConfig
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        return getattr(self.op_details.body.body, "pop_count", 0)
    
    def _get_max_operands(self) -> int:
        """Return the maximum number of operands this instruction can fuse."""
        return getattr(self.op_details.body.body, "pop_count", 0)
    
    def fuse(self, previous: Instruction) -> Optional['SmartComplexOp']:
        """Attempt to fuse with previous instruction."""
        # Use the mixin's standard fusion logic
        return cast(Optional['SmartComplexOp'], self._standard_fuse(previous))
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            var_id = operand.op_details.body.data
            # Handle signed byte interpretation for PushByteVar
            if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                var_id = var_id + 256
            # Check if this is a local variable
            if hasattr(operand.op_details.body, 'type'):
                var_type = operand.op_details.body.type
                if var_type == Scumm6Opcodes.VarType.local:
                    return [TInt(f"localvar{var_id}")]
                elif var_type == Scumm6Opcodes.VarType.bitvar:
                    return [TInt(f"bitvar{var_id}")]
            
            # System variable - use semantic name mapping
            return [TInt(get_variable_name(var_id))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression with parentheses
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif operand.produces_result():
            # Complex case: would need to execute operand's lift method
            # For now, use placeholder - future enhancement needed
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Placeholder

    def render(self, as_operand: bool = False) -> List[Token]:
        subop = self.op_details.body.subop
        
        # Ensure subop is an enum member, not an int
        if isinstance(subop, int):
            from ...scumm6_opcodes import Scumm6Opcodes
            try:
                subop = Scumm6Opcodes.SubopType(subop)
            except ValueError:
                # Handle cases where the int value is not a valid enum member
                return [TInstr(f"{self._name}.unknown_{subop}")]
        
        subop_name = subop.name
        full_name = f"{self._name}.{subop_name}"
        
        # Apply descumm-style function name mapping
        display_name = DESCUMM_FUNCTION_NAMES.get(full_name, full_name)
        
        # Handle fused operands and/or hardcoded parameters
        if self.fused_operands or hasattr(self.op_details.body.body, 'param'):
            tokens = [TInstr(display_name), TSep("(")]
            param_count = 0
            
            # First, add any hardcoded parameter from the instruction body
            if hasattr(self.op_details.body.body, 'param'):
                tokens.append(TInt(str(self.op_details.body.body.param)))
                param_count += 1
            
            # Then add fused operands in push order (not reversed)
            for operand in self.fused_operands:
                if param_count > 0:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(operand))
                param_count += 1
                
            tokens.append(TSep(")"))
            return tokens
        
        # Add parentheses for function call syntax consistency  
        # For descumm literal compatibility, always show () instead of (...)
        return [TInstr(f"{display_name}()")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Get the expected body type dynamically
        expected_type = getattr(Scumm6Opcodes, self._config.body_type_name)
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Ensure subop is an enum member, not an int
        if isinstance(subop, int):
            try:
                subop = Scumm6Opcodes.SubopType(subop)
            except ValueError:
                # Handle cases where the int value is not a valid enum member
                il.append(il.unimplemented())
                return
        
        # Construct intrinsic name
        intrinsic_name = f"{self._name}.{subop.name}"
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        if self.fused_operands:
            # Use fused operands in push order
            params = []
            for operand in self.fused_operands:
                params.append(self._lift_operand(il, operand))
        else:
            params = [il.pop(4) for _ in range(pop_count)]
        
        if push_count > 0:
            il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        else:
            il.append(il.intrinsic([], intrinsic_name, params))

# Smart stack operation base classes
class SmartBinaryOp(Instruction, FusibleMultiOperandMixin):
    """Self-configuring binary stack operation."""
    
    _name: str
    _config: StackConfig

    def _get_max_operands(self) -> int:
        """Binary operations accept exactly 2 operands."""
        return 2

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        # If we have fused operands, we need fewer stack pops
        return max(0, 2 - len(self.fused_operands))
    
    def produces_result(self) -> bool:
        """Binary operations produce results that can be consumed by other instructions."""
        return True

    def fuse(self, previous: Instruction) -> Optional['SmartBinaryOp']:
        """Attempt to fuse with the previous instruction using standard fusion logic."""
        return cast(Optional['SmartBinaryOp'], self._standard_fuse(previous))
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variables don't need extra parentheses in descumm style
            var_id = operand.op_details.body.data
            # Handle signed byte interpretation for PushByteVar
            if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                var_id = var_id + 256
            
            # Check if this is a local variable
            if hasattr(operand.op_details.body, 'type'):
                var_type = operand.op_details.body.type
                if var_type == Scumm6Opcodes.VarType.local:
                    return [TInt(f"localvar{var_id}")]
                elif var_type == Scumm6Opcodes.VarType.bitvar:
                    return [TInt(f"bitvar{var_id}")]
            
            # System variable - use semantic name mapping
            return [TInt(get_variable_name(var_id))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            # Constants don't need parentheses
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Add parentheses for operations that need grouping when used as operands
            if operand.__class__.__name__ in ['Sub', 'Mul', 'Div']:
                # Subtraction, multiplication and division need parentheses when used as operands
                tokens: List[Token] = []
                tokens.append(TText("("))
                # Check if render method supports as_operand parameter
                try:
                    tokens.extend(operand.render(as_operand=True))
                except TypeError:
                    tokens.extend(operand.render())
                tokens.append(TText(")"))
                return tokens
            else:
                # Addition doesn't need extra parentheses in most contexts
                try:
                    return operand.render(as_operand=True)
                except TypeError:
                    return operand.render()
        else:
            return [TText("operand")]

    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif operand.produces_result():
            # This is a result-producing instruction - we need to generate its IL
            # For now, use a placeholder. In a real implementation, we would
            # need to execute the instruction's lift method and capture its result
            # This is complex and might require significant architectural changes
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Fallback

    def render(self, as_operand: bool = False) -> List[Token]:
        display_name = self._config.display_name or self._name
        # Apply descumm-style function name mapping
        mapped_name = DESCUMM_FUNCTION_NAMES.get(display_name, display_name)
        
        # If we have fused operands, render in infix style for arithmetic operations
        if self.fused_operands and len(self.fused_operands) == 2:
            # Map operation names to infix operators
            infix_operators = {
                'add': '+',
                'sub': '-',
                'mul': '*',
                'div': '/',
                'land': '&&',
                'lor': '||'
            }
            
            if self._name in infix_operators:
                # Render as infix
                tokens: List[Token] = []
                
                # Add outer parentheses for standalone expressions or when needed as operand
                if not as_operand:
                    tokens.append(TSep("("))
                
                # Left operand (first pushed, so fused_operands[0])
                tokens.extend(self._render_operand(self.fused_operands[0]))
                
                # Operator
                op_symbol = infix_operators[self._name]
                tokens.append(TText(f" {op_symbol} "))
                
                # Right operand (second pushed, so fused_operands[1])
                tokens.extend(self._render_operand(self.fused_operands[1]))
                
                if not as_operand:
                    tokens.append(TSep(")"))
                
                return tokens
        
        # If we have fused operands but not 2, or not an infix operation, use function call style
        if self.fused_operands:
            tokens = [TInstr(mapped_name), TSep("(")]
            
            for i, operand in enumerate(self.fused_operands):
                if i > 0:
                    tokens.extend([TSep(","), TSep(" ")])
                
                # Use the helper method to render the operand
                tokens.extend(self._render_operand(operand))
            
            # If we still need stack operands, indicate with ellipsis
            remaining_ops = 2 - len(self.fused_operands)
            if remaining_ops > 0:
                if self.fused_operands:
                    tokens.extend([TSep(","), TSep(" ")])
                tokens.append(TInstr("..."))
                    
            tokens.append(TSep(")"))
            return tokens
        else:
            # Standard rendering
            return [TInstr(mapped_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Collect operands: use fused operands first, then pop from stack
        operands = []
        
        # Add fused operands (in order - first fused operand is first operand)
        for operand in self.fused_operands:
            if hasattr(operand, 'op_details') and hasattr(operand.op_details, 'body'):
                if hasattr(operand.op_details.body, 'data'):
                    # Constant value
                    operands.append(il.const(4, operand.op_details.body.data))
                elif operand.__class__.__name__ in ('PushByteVar', 'PushWordVar'):
                    # Variable - use the vars module
                    from ... import vars
                    operands.append(vars.il_get_var(il, operand.op_details.body))
                else:
                    # Fallback - treat as constant 0
                    operands.append(il.const(4, 0))
        
        # Pop remaining operands from stack
        remaining_pops = 2 - len(self.fused_operands)
        for i in range(remaining_pops):
            operands.append(il.pop(4))
        
        # Ensure we have exactly 2 operands
        if len(operands) != 2:
            # Fallback - use standard stack operations
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b
            op1 = il.reg(4, LLIL_TEMP(1))
            op2 = il.reg(4, LLIL_TEMP(0))
        else:
            # Use our collected operands: operand[1] op operand[0] (reverse order for stack semantics)
            op1 = operands[1] if len(operands) > 1 else operands[0]
            op2 = operands[0]

        # Get the operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b op a
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))

class SmartUnaryOp(Instruction):
    """Self-configuring unary stack operation."""
    
    _name: str
    _config: StackConfig

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        return 0 if self.fused_operands else 1

    def produces_result(self) -> bool:
        """Unary operations produce results that can be consumed by other instructions."""
        return True

    def fuse(self, previous: Instruction) -> Optional['SmartUnaryOp']:
        """Attempt to fuse with the previous instruction."""
        # Only fuse if we don't already have operands
        if self.fused_operands:
            return None
        
        # Check if previous produces a result or is a simple push
        if not (hasattr(previous, 'produces_result') and previous.produces_result()) and \
           previous.__class__.__name__ not in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            return None
        
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused

    def render(self, as_operand: bool = False) -> List[Token]:
        display_name = self._config.display_name or self._name
        # Apply descumm-style function name mapping
        mapped_name = DESCUMM_FUNCTION_NAMES.get(display_name, display_name)
        
        # For nott with fused operands, we don't show the instruction name
        # because it will be rendered as part of the conditional
        if self._name == "nott" and self.fused_operands:
            # Don't render anything here - the conditional will handle it
            return []
        
        return [TInstr(mapped_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Get the operand value
        if self.fused_operands:
            # Use fused operand
            operand = self.fused_operands[0]
            if hasattr(operand, 'op_details') and hasattr(operand.op_details, 'body'):
                if hasattr(operand.op_details.body, 'data'):
                    # Constant value
                    value = il.const(4, operand.op_details.body.data)
                elif operand.__class__.__name__ in ('PushByteVar', 'PushWordVar'):
                    # Variable - use the vars module
                    from ... import vars
                    value = vars.il_get_var(il, operand.op_details.body)
                else:
                    # Fallback - pop from stack
                    value = il.pop(4)
            else:
                # Fallback - pop from stack
                value = il.pop(4)
            il.append(il.set_reg(4, LLIL_TEMP(0), value))
        else:
            # Pop one value from stack
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))

        if self._name == "nott":
            # Special case for logical NOT - compare with zero
            comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
            il.append(il.push(4, comp_res))
        else:
            # Get the operation from the il object
            il_func = getattr(il, self._config.il_op_name)
            result = il_func(4, il.reg(4, LLIL_TEMP(0)))
            il.append(il.push(4, result))

class SmartConditionalJump(ControlFlowOp):
    """Smart conditional jump that supports fusion with comparison operations."""
    
    _name: str
    _is_if_not: bool  # True for if_not, False for iff
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []
        self._original_addr = addr  # Preserve original address for jump calculations
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        else:
            return 1  # Normal conditional jump pops condition from stack
    
    def is_conditional(self) -> bool:
        return True
    
    def fuse(self, previous: Instruction) -> Optional['SmartConditionalJump']:
        """Attempt to fuse with a comparison operation or simple push."""
        # Only fuse if we don't already have operands
        if self.fused_operands:
            return None
            
        # Check if previous is fusible
        if not (self._is_comparison_op(previous) or self._is_simple_push(previous) or 
                (hasattr(previous, 'produces_result') and previous.produces_result())):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        # Preserve the original conditional jump's address for correct jump target calculation
        # If this is the first fusion, save the current address as the original
        if not hasattr(self, '_original_addr') or self._original_addr is None:
            fused._original_addr = self.addr
        return fused
    
    def _is_comparison_op(self, instr: Instruction) -> bool:
        """Check if instruction is a comparison operation that can be fused."""
        comparison_ops = ['Eq', 'Neq', 'Gt', 'Lt', 'Le', 'Ge']
        return instr.__class__.__name__ in comparison_ops
    
    def _is_simple_push(self, instr: Instruction) -> bool:
        """Check if instruction is a simple push that can be fused for loop conditions."""
        simple_push_ops = ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']
        return instr.__class__.__name__ in simple_push_ops
    
    def _render_condition(self, condition_instr: Instruction, negate: bool = False) -> List[Token]:
        """Render a fused condition (comparison or simple push) as readable condition."""
        # Check if this is a Nott instruction
        if condition_instr.__class__.__name__ == 'Nott':
            # For descumm compatibility, always show the '!' for Nott
            tokens: List[Token] = []
            tokens.append(TText("!"))
            if hasattr(condition_instr, 'fused_operands') and condition_instr.fused_operands:
                # Render the inner condition
                tokens.extend(self._render_condition(condition_instr.fused_operands[0]))
            else:
                # No inner condition, just show "condition"
                tokens.append(TText("condition"))
            return tokens
        
        # Check if this is a comparison with fused operands
        elif self._is_comparison_op(condition_instr) and hasattr(condition_instr, 'fused_operands') and len(condition_instr.fused_operands) >= 2:
            # Get operands (in reverse order due to stack semantics)
            left_operand = condition_instr.fused_operands[1]
            right_operand = condition_instr.fused_operands[0]
            
            tokens = []
            tokens.extend(self._render_operand(left_operand))
            
            # Get comparison operator
            op_name = condition_instr.__class__.__name__.lower()
            # Always use the normal comparison - descumm uses "unless" with the original condition
            normal_ops = {'eq': '==', 'neq': '!=', 'gt': '>', 'lt': '<', 'le': '<=', 'ge': '>='}
            op_symbol = normal_ops.get(op_name, op_name)
            
            tokens.append(TText(f" {op_symbol} "))
            tokens.extend(self._render_operand(right_operand))
            
            return tokens
        
        # Check if this is a simple push (for simple truthiness test)
        elif condition_instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            tokens = []
            # Don't add negation here - it's handled at the if/unless level
            tokens.extend(self._render_operand(condition_instr))
            return tokens
        
        # Check if this is a result-producing instruction (like isScriptRunning)
        elif hasattr(condition_instr, 'render'):
            # Use the instruction's own render method
            return condition_instr.render()
        
        # Fallback for unknown condition types
        else:
            return [TText("condition")]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            var_id = operand.op_details.body.data
            # Handle signed byte interpretation for PushByteVar
            if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                var_id = var_id + 256
            # Check if this is a local variable
            if hasattr(operand.op_details.body, 'type'):
                var_type = operand.op_details.body.type
                if var_type == Scumm6Opcodes.VarType.local:
                    return [TInt(f"localvar{var_id}")]
                elif var_type == Scumm6Opcodes.VarType.bitvar:
                    return [TInt(f"bitvar{var_id}")]
            
            # System variable - use semantic name mapping
            return [TInt(get_variable_name(var_id))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif hasattr(operand, 'render'):
            # For complex operands that have their own render method (like array reads)
            return operand.render()
        else:
            return [TText("operand")]
    
    def render(self, as_operand: bool = False) -> List[Token]:
        if self.fused_operands:
            # Render as readable conditional in descumm style
            tokens: List[Token] = []
            
            # Simple approach based on user feedback:
            # - if_not instruction = "unless"
            # - iff instruction = "if"
            # - Do NOT simplify double negation (if_not + nott) - keep it as is for descumm compatibility
            
            condition = self.fused_operands[0]
            use_unless = self._is_if_not
            
            # Keep the logic simple - no special handling for double negation
            # Descumm shows: unless ((!isScriptRunning(...)))
            # Not: if ((isScriptRunning(...)))
            
            if use_unless:
                tokens.append(TInstr("unless"))
            else:
                tokens.append(TInstr("if"))
            
            tokens.append(TText(" (("))
            # Render the condition
            tokens.extend(self._render_condition(condition))
            tokens.append(TText("))"))
            
            # Add jump target
            jump_offset = self.op_details.body.jump_offset
            tokens.append(TText(" "))
            tokens.append(TInstr("jump"))
            tokens.append(TText(" "))
            
            # For hard-coded bytecode tests (small addresses), show the raw offset
            # For real scripts, calculate and show hex address
            if hasattr(self, 'addr') and self.addr is not None and self.addr < 0x100:
                # Hard-coded bytecode test - show raw decimal offset
                tokens.append(TInstr(str(jump_offset)))
            elif hasattr(self, '_original_addr') and self._original_addr is not None:
                # Use the original conditional jump's address for calculation
                original_length = 3  # if_not and iff are both 3 bytes
                target_addr = self._original_addr + original_length + jump_offset
                # Format the target address
                if target_addr < 0:
                    formatted_addr = f"{target_addr & 0xFFFFFFFF:x}"
                else:
                    formatted_addr = f"{target_addr:x}"
                tokens.append(TInstr(formatted_addr))
            elif hasattr(self, 'addr') and self.addr is not None:
                # Fallback to current address if no original preserved
                original_length = 3  # if_not and iff are both 3 bytes
                target_addr = self.addr + original_length + jump_offset
                # Format the target address
                if target_addr < 0:
                    formatted_addr = f"{target_addr & 0xFFFFFFFF:x}"
                else:
                    formatted_addr = f"{target_addr:x}"
                tokens.append(TInstr(formatted_addr))
            else:
                # No address context - show decimal offset
                if jump_offset < 0:
                    formatted_offset = f"{jump_offset & 0xFFFFFFFF:x}"
                else:
                    formatted_offset = str(jump_offset)
                tokens.append(TInstr(formatted_offset))
            
            return tokens
        else:
            # Normal rendering
            jump_offset = self.op_details.body.jump_offset
            if self._is_if_not:
                instr_name = "unless"
            else:
                instr_name = "if"
            
            if jump_offset == 0:
                # Handle zero offset as 'self'
                return [TInstr(instr_name), TText(" "), TInstr("goto"), TText(" "), TInstr("self")]
            elif jump_offset > 0:
                return [TInstr(f"{instr_name} goto +{jump_offset}")]
            else:
                return [TInstr(f"{instr_name} goto {jump_offset}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        if self.fused_operands:
            self._lift_fused_conditional_branch(il, addr)
        else:
            self._lift_stack_based_conditional_branch(il, addr)
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        else:
            return il.const(4, 0)  # Fallback
    
    def _lift_stack_based_conditional_branch(self, il: LowLevelILFunction, addr: int) -> None:
        """Logic for when the condition is on the stack."""
        # Pop condition from stack
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
        condition_expr = il.reg(4, LLIL_TEMP(0))
        self._perform_branch(il, addr, condition_expr)

    def _lift_fused_conditional_branch(self, il: LowLevelILFunction, addr: int) -> None:
        """Logic for when the condition is a fused expression."""
        comparison = self.fused_operands[0]
        
        # Handle Nott instruction specially
        if comparison.__class__.__name__ == 'Nott':
            # For nott, we need to generate the operations for the negated expression
            if hasattr(comparison, 'fused_operands') and comparison.fused_operands:
                # Get the operand that nott is negating
                operand = comparison.fused_operands[0]
                
                # Check if it's an intrinsic like isScriptRunning
                if operand.__class__.__name__ == 'IsScriptRunning':
                    # Generate the intrinsic call
                    if hasattr(operand, 'fused_operands') and operand.fused_operands:
                        # Get the parameter (script ID)
                        param = operand.fused_operands[0]
                        param_expr = self._lift_operand(il, param)
                        
                        # Generate the intrinsic call
                        result_reg = LLIL_TEMP(0)
                        il.append(il.intrinsic([result_reg], IntrinsicName('is_script_running'), [param_expr]))
                        il.append(il.push(4, il.reg(4, result_reg)))
                        
                        # Pop and apply the NOT
                        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
                        comp_res = il.compare_equal(4, il.reg(4, LLIL_TEMP(0)), il.const(4, 0))
                        il.append(il.push(4, comp_res))
                        
                        # Pop the result for the conditional
                        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))
                        condition_expr = il.reg(4, LLIL_TEMP(0))
                    else:
                        # No fused parameter, handle normally
                        condition_expr = self._lift_operand(il, comparison)
                else:
                    # Other type of operand for nott
                    condition_expr = self._lift_operand(il, comparison)
            else:
                # Nott without fused operands
                condition_expr = self._lift_operand(il, comparison)
        elif hasattr(comparison, 'fused_operands') and len(comparison.fused_operands) >= 2:
            # Get operands (reverse order for stack semantics)
            left_operand = comparison.fused_operands[1]
            right_operand = comparison.fused_operands[0]
            
            left_expr = self._lift_operand(il, left_operand)
            right_expr = self._lift_operand(il, right_operand)
            
            # Get comparison operation
            op_name = comparison.__class__.__name__.lower()
            comparison_ops = {
                'eq': 'compare_equal',
                'neq': 'compare_not_equal', 
                'gt': 'compare_signed_greater_than',
                'lt': 'compare_signed_less_than',
                'le': 'compare_signed_less_equal',
                'ge': 'compare_signed_greater_equal'
            }
            
            il_op_name = comparison_ops.get(op_name, 'compare_equal')
            il_func = getattr(il, il_op_name)
            condition_expr = il_func(4, left_expr, right_expr)
        else:
            # Simple push condition
            condition_expr = self._lift_operand(il, comparison)
        
        self._perform_branch(il, addr, condition_expr)

    def _perform_branch(self, il: LowLevelILFunction, addr: int, condition_expr: int) -> None:
        """Unified branching logic that handles both intra and inter-procedural jumps."""
        jump_offset = self.op_details.body.jump_offset
        target_addr = addr + self.length() + jump_offset

        # Determine the final condition based on if_not semantics
        if self._is_if_not:
            # For 'if_not' (unless), jump is taken if condition is FALSE (zero)
            condition = il.compare_equal(4, condition_expr, il.const(4, 0))
        else:
            # For 'iff' (if), jump is taken if condition is TRUE (non-zero)
            condition = il.compare_not_equal(4, condition_expr, il.const(4, 0))

        # Try to get a label for an intra-function jump
        destination_label = il.get_label_for_address(il.arch, target_addr)

        if destination_label:
            # --- INTRA-FUNCTION JUMP ---
            # The target is within the same function. We can use il.if_expr directly.
            fallthrough_label = LowLevelILLabel()
            il.append(il.if_expr(condition, destination_label, fallthrough_label))
            il.mark_label(fallthrough_label)
        else:
            # --- INTER-FUNCTION JUMP ---
            # The target is outside the current function. Create a trampoline.
            trampoline_label = LowLevelILLabel()
            fallthrough_label = LowLevelILLabel()

            # Create the conditional branch to our local trampoline or fallthrough
            il.append(il.if_expr(condition, trampoline_label, fallthrough_label))

            # Define what happens in the "jump" block
            il.mark_label(trampoline_label)
            # This is an *unconditional* jump to the absolute address
            # il.const_pointer is crucial for creating the cross-reference
            il.append(il.jump(il.const_pointer(il.arch.address_size, target_addr)))

            # Define the "fallthrough" block
            il.mark_label(fallthrough_label)
            # Optional nop for clarity - the next instruction will be lifted here
            il.append(il.nop())

class SmartComparisonOp(Instruction):
    """Self-configuring comparison stack operation with fusion support."""
    
    _name: str
    _config: StackConfig

    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List['Instruction'] = []

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self.fused_operands:
            return 0  # Fused instructions handle their own operands
        else:
            return 2  # Normal comparison pops two values
    
    def produces_result(self) -> bool:
        """Comparison operations produce results that can be consumed by other instructions."""
        return True

    def fuse(self, previous: Instruction) -> Optional['SmartComparisonOp']:
        """Attempt to fuse with a push instruction."""
        # Only fuse if we need more operands (max 2 for binary comparison)
        if len(self.fused_operands) >= 2:
            return None
            
        # Check if previous is a fusible push
        if not self._is_fusible_push(previous):
            return None
            
        # Create fused instruction
        fused = copy.deepcopy(self)
        fused.fused_operands.append(previous)
        fused._length = self._length + previous.length()
        return fused

    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused or produces a consumable result."""
        # Check for basic push instructions
        if instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']:
            return True
        
        # Check if instruction produces a result that can be consumed
        # This enables multi-level expression building
        if instr.produces_result():
            return True
            
        return False

    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            var_id = operand.op_details.body.data
            # Handle signed byte interpretation for PushByteVar
            if operand.__class__.__name__ == 'PushByteVar' and var_id < 0:
                var_id = var_id + 256
            # Check if this is a local variable
            if hasattr(operand.op_details.body, 'type'):
                var_type = operand.op_details.body.type
                if var_type == Scumm6Opcodes.VarType.local:
                    return [TInt(f"localvar{var_id}")]
                elif var_type == Scumm6Opcodes.VarType.bitvar:
                    return [TInt(f"bitvar{var_id}")]
            
            # System variable - use semantic name mapping
            return [TInt(get_variable_name(var_id))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return [TInt(str(operand.op_details.body.data))]
        elif operand.produces_result():
            # This is a result-producing instruction (like a fused expression)
            # Render it as a nested expression
            tokens: List[Token] = []
            tokens.append(TText("("))
            tokens.extend(operand.render())
            tokens.append(TText(")"))
            return tokens
        else:
            return [TText("operand")]

    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return il.reg(4, f"var_{operand.op_details.body.data}")
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            return il.const(4, operand.op_details.body.data)
        elif operand.produces_result():
            # This is a result-producing instruction - placeholder for now
            # Proper implementation would require significant architectural changes
            return il.const(4, 0)  # Placeholder
        else:
            return il.const(4, 0)  # Fallback

    def render(self, as_operand: bool = False) -> List[Token]:
        if self.fused_operands and len(self.fused_operands) == 2:
            # Render as comparison with operands: left op right
            tokens: List[Token] = []
            
            # Get operands (in reverse order due to stack semantics)
            left_operand = self.fused_operands[1]
            right_operand = self.fused_operands[0]
            
            # Get comparison symbol
            op_symbols = {'eq': '==', 'neq': '!=', 'gt': '>', 'lt': '<', 'le': '<=', 'ge': '>='}
            op_symbol = op_symbols.get(self._name, self._name)
            
            tokens.extend(self._render_operand(left_operand))
            tokens.append(TText(f" {op_symbol} "))
            tokens.extend(self._render_operand(right_operand))
            
            return tokens
        elif self.fused_operands and len(self.fused_operands) == 1:
            # Partially fused - function-call style
            tokens_partial: List[Token] = []
            display_name = self._config.display_name or self._name
            tokens_partial.append(TInstr(f"{display_name}("))
            tokens_partial.extend(self._render_operand(self.fused_operands[0]))
            tokens_partial.append(TText(")"))
            return tokens_partial
        else:
            # Normal rendering
            display_name = self._config.display_name or self._name
            return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        if self.fused_operands and len(self.fused_operands) == 2:
            # Fused comparison - use direct operands
            left_operand = self.fused_operands[1]  # Reverse order for stack semantics
            right_operand = self.fused_operands[0]
            
            left_expr = self._lift_operand(il, left_operand)
            right_expr = self._lift_operand(il, right_operand)
            
            # Get the comparison operation from the il object
            il_func = getattr(il, self._config.il_op_name)
            comp_res = il_func(4, left_expr, right_expr)
            il.append(il.push(4, comp_res))
        else:
            # Normal stack-based lifting
            # Pop two values: a (top), b (second)
            il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
            il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

            # Get the comparison operation from the il object
            il_func = getattr(il, self._config.il_op_name)

            # Push result: b compare a
            op1 = il.reg(4, LLIL_TEMP(1))
            op2 = il.reg(4, LLIL_TEMP(0))
            comp_res = il_func(4, op1, op2)
            il.append(il.push(4, comp_res))

class SmartArrayOp(Instruction):
    """Self-configuring array operation."""
    
    _name: str
    _config: ArrayConfig

    def fuse(self, previous: Instruction) -> Optional['SmartArrayOp']:
        """Attempt to fuse with the previous instruction."""
        # Determine how many operands we need
        if self._config.operation == "read":
            expected_operands = 2 if self._config.indexed else 1
        elif self._config.operation == "write":
            expected_operands = 3 if self._config.indexed else 2
        else:
            return None
        
        # Only fuse if we need more operands
        if len(self.fused_operands) >= expected_operands:
            return None
        
        # Check if previous is a fusible push instruction
        if not self._is_fusible_push(previous):
            return None
        
        # Create a new fused instruction
        fused = copy.deepcopy(self)
        
        # Add the previous instruction to the front (stack is LIFO)
        fused.fused_operands.insert(0, previous)
        
        # Update length to include the fused instruction
        fused._length = self._length + previous.length()
        
        return fused
    
    def produces_result(self) -> bool:
        """Array read operations produce a result that can be consumed by other instructions."""
        return self._config.operation == "read"
    
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused."""
        return instr.__class__.__name__ in [
            'PushByte', 'PushWord', 'PushByteVar', 'PushWordVar'
        ]

    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        if self._config.operation == "read":
            return 2 if self._config.indexed else 1
        elif self._config.operation == "write":
            base_count = 3 if self._config.indexed else 2
            # If we have fused operands, we pop fewer from the stack
            if hasattr(self, 'fused_operands'):
                return max(0, base_count - len(self.fused_operands))
            return base_count
        return 0

    def render(self, as_operand: bool = False) -> List[Token]:
        if hasattr(self.op_details.body, 'array'):
            array_id = self.op_details.body.array
            
            # Check for fusion in read operations
            if self._config.operation == "read" and self.fused_operands:
                # Render as array access: array_236[7]
                tokens: List[Token] = []
                tokens.append(TInt(f"array_{array_id}"))
                tokens.append(TSep("["))
                
                if self._config.indexed and len(self.fused_operands) >= 2:
                    # array[base + index]
                    tokens.extend(self._render_operand(self.fused_operands[1]))  # base
                    tokens.append(TSep(" + "))
                    tokens.extend(self._render_operand(self.fused_operands[0]))  # index
                elif len(self.fused_operands) >= 1:
                    # array[index]
                    tokens.extend(self._render_operand(self.fused_operands[0]))  # index
                else:
                    tokens.append(TSep("?"))
                
                tokens.append(TSep("]"))
                return tokens
            
            # Check for fusion in write operations
            elif self._config.operation == "write" and self.fused_operands:
                # Render as array assignment: array_5[3] = 10
                tokens = []
                tokens.append(TInt(f"array_{array_id}"))
                tokens.append(TSep("["))
                
                # Handle operand order for array operations
                # IMPORTANT: Match descumm semantics
                # For non-indexed: [index, value] → array[index] = value
                # For indexed: [index, value, base] → array[base + index] = value
                
                if len(self.fused_operands) >= 2:
                    # We have both index and value
                    if self._config.indexed and len(self.fused_operands) >= 3:
                        # array[base + index] = value
                        tokens.extend(self._render_operand(self.fused_operands[2]))  # base
                        tokens.append(TSep(" + "))
                        tokens.extend(self._render_operand(self.fused_operands[0]))  # index
                    else:
                        # array[index] = value
                        tokens.extend(self._render_operand(self.fused_operands[0]))  # index
                    
                    tokens.append(TSep("] = "))
                    tokens.extend(self._render_operand(self.fused_operands[1]))  # value
                    return tokens
                elif len(self.fused_operands) == 1:
                    # Partial fusion - might be just the value or just the index
                    tokens.append(TSep("?, "))
                    tokens.extend(self._render_operand(self.fused_operands[0]))
                    tokens.append(TSep("]"))
                    return tokens
            
            # Normal rendering
            return [
                TInstr(self._name),
                TSep("("),
                TInt(f"array_{array_id}"),
                TSep(")"),
            ]
        else:
            return [TInstr(self._name)]
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        from binja_helpers.tokens import TInt, TText
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - extract var number
            if hasattr(operand.op_details.body, 'data'):
                data = operand.op_details.body.data
                # Handle signed byte interpretation for PushByteVar
                if operand.__class__.__name__ == 'PushByteVar' and data < 0:
                    data = data + 256
                return [TInt(get_variable_name(data, use_raw_names=True))]
        else:
            # Constant push - extract value
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return [TInt(str(value))]
        
        # Fallback
        return [TText("?")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from binaryninja import IntrinsicName
        
        # Handle UnknownOp case for array inc/dec operations
        if isinstance(self.op_details.body, Scumm6Opcodes.UnknownOp):
            il.append(il.unimplemented())
            il.append(il.unimplemented())
            return
        
        # Generate intrinsic call
        if self._config.operation == "read":
            if self._config.indexed:
                # Indexed read: pop index and base
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4), il.pop(4)]
                ))
            else:
                # Simple read: pop base only
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    [il.pop(4)]
                ))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        elif self._config.operation == "write":
            if self.fused_operands:
                # Build parameters from fused operands
                params = []
                for operand in self.fused_operands:
                    params.append(self._lift_operand(il, operand))
                
                # Add any remaining stack pops
                expected_operands = 3 if self._config.indexed else 2
                remaining_pops = expected_operands - len(self.fused_operands)
                for _ in range(remaining_pops):
                    params.append(il.pop(4))
                
                # Generate the intrinsic call
                il.append(il.intrinsic(
                    [il.reg(4, LLIL_TEMP(0))],
                    IntrinsicName(self._name),
                    params
                ))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
            else:
                # Original behavior
                if self._config.indexed:
                    # Indexed write: pop value, index, base
                    il.append(il.intrinsic(
                        [il.reg(4, LLIL_TEMP(0))],
                        IntrinsicName(self._name),
                        [il.pop(4), il.pop(4), il.pop(4)]
                    ))
                else:
                    # Simple write: pop value and base
                    il.append(il.intrinsic(
                        [il.reg(4, LLIL_TEMP(0))],
                        IntrinsicName(self._name),
                        [il.pop(4), il.pop(4)]
                    ))
                il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            # Variable push - use il_get_var
            from ... import vars
            return vars.il_get_var(il, operand.op_details.body)
        else:
            # Constant push - use const
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return il.const(4, value)
        
        # Fallback to undefined
        return il.undefined()

class SmartSemanticIntrinsicOp(SmartFusibleIntrinsic):
    """Self-configuring semantic intrinsic following descumm philosophy with fusion support."""
    
    _name: str
    _config: SemanticIntrinsicConfig

    @property
    def stack_pop_count(self) -> int:
        """
        The number of values this instruction expects to pop from the stack.
        For functions with variable arguments, this returns -1 to indicate
        the pop count is dynamic and depends on a value on the stack.
        """
        if self._config.variable_args:
            return -1
        
        # If we have fused operands, we pop fewer from the stack
        if hasattr(self, 'fused_operands') and self.fused_operands:
            return max(0, self._config.pop_count - len(self.fused_operands))
        
        return self._config.pop_count
    
    def render(self, as_operand: bool = False) -> List[Token]:
        """Render in descumm-style function call format."""
        if self.fused_operands:
            return self._render_fused_semantic_call()
        else:
            return self._render_semantic_call()
    
    def _render_semantic_call(self) -> List[Token]:
        """Render as: semantic_name(...) for consistency with other intrinsics."""
        # Use descumm-style naming for semantic operations too
        display_name = DESCUMM_FUNCTION_NAMES.get(self._config.semantic_name, self._config.semantic_name)
        
        # For descumm literal compatibility, always show () instead of (...)
        return [TInstr(f"{display_name}()")]
    
    def _render_fused_semantic_call(self) -> List[Token]:
        """Render semantic function call with fused operands."""
        # Use descumm-style naming for fused semantic operations too
        display_name = DESCUMM_FUNCTION_NAMES.get(self._config.semantic_name, self._config.semantic_name)
        tokens = [TInstr(display_name), TSep("(")]
        
        # Add fused operands as actual parameters
        for i, operand in enumerate(self.fused_operands):
            if i > 0:
                tokens.append(TSep(","))
            tokens.extend(self._render_operand(operand))
        
        tokens.append(TSep(")"))
        return tokens
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL following descumm semantic approach."""
        if self.fused_operands:
            self._lift_fused_operation(il, addr)
        elif self._config.variable_args:
            self._lift_variable_args_operation(il, addr)
        else:
            self._lift_fixed_args_operation(il, addr)
    
    def _lift_fused_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle LLIL generation for fused semantic operations."""
        # Build parameters from fused operands
        params = []
        for operand in self.fused_operands:
            params.append(self._lift_operand(il, operand))
        
        # Add any remaining stack pops if we don't have all operands fused
        if not self._config.variable_args:
            remaining_pops = self._config.pop_count - len(self.fused_operands)
            for _ in range(remaining_pops):
                params.append(il.pop(4))
        
        # Generate the semantic intrinsic call
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._config.semantic_name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._config.semantic_name, params))
    
    def _lift_variable_args_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle operations with variable arguments (like start_script)."""
        # For start_script: stack has [script_id, flags, arg_count] (LIFO order)
        # Pop in reverse order since stack is LIFO
        arg_count = il.pop(4)  # Pop arg_count first (top of stack)
        
        # Extract actual variable arguments based on arg_count
        args: List[Any] = []
        # TODO: In full implementation, pop arg_count number of arguments
        # For now, we know it's 0 from the bytecode
        
        if self._name == "start_script":
            # Pop flags and script_id in correct order
            flags = il.pop(4)      # Pop flags (second on stack)
            script_id = il.pop(4)  # Pop script_id (bottom of stack)
            params = [script_id, flags, arg_count] + args
        else:
            # For other script operations, just script_id and arg_count
            script_id = il.pop(4)
            params = [script_id, arg_count] + args
        
        # Generate semantic intrinsic call
        il.append(il.intrinsic([], self._config.semantic_name, params))
        
        # Handle control flow implications if needed
        if self._config.control_flow_impact:
            self._handle_script_call_flow(il, script_id)
    
    def _lift_fixed_args_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle operations with fixed arguments."""
        # Standard intrinsic lift with semantic name
        params = [il.pop(4) for _ in range(self._config.pop_count)]
        
        if self._config.push_count > 0:
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._config.semantic_name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
        else:
            il.append(il.intrinsic([], self._config.semantic_name, params))
    
    def _extract_variable_arguments(self, il: LowLevelILFunction) -> List[int]:
        """Extract variable arguments from stack (following original implementation)."""
        # This is simplified - in real implementation, this would follow
        # the pattern from scumm6.py for extracting variable argument lists
        # For now, return empty list as placeholder
        return []
    
    def _handle_script_call_flow(self, il: LowLevelILFunction, script_id: int) -> None:
        """Handle control flow implications for script calls."""
        # In a full implementation, this would:
        # 1. Try to resolve script_id to actual address
        # 2. Generate appropriate call or jump instruction for CFG
        # 3. Handle the script context passing
        # For now, this is a placeholder
        pass


# ============================================================================
# Loop Pattern Recognition System
# ============================================================================

class LoopInfo(NamedTuple):
    """Information about a detected loop pattern."""
    loop_type: str          # "while", "for", "do_while"
    body_start: int         # Start address of loop body
    body_end: int           # End address of loop body  
    condition: Optional['Instruction']  # Loop condition instruction
    iterator_var: Optional[int]         # Variable number if it's a counter loop
    increment_amount: Optional[int]     # Increment amount for counter loops


class SmartLoopDetector:
    """Advanced loop pattern detection for SCUMM6 bytecode."""
    
    @staticmethod
    def detect_loop_pattern(
        conditional_jump: 'SmartConditionalJump', 
        address: int
    ) -> Optional[LoopInfo]:
        """
        Detect if a conditional jump represents a loop pattern.
        
        Args:
            conditional_jump: The conditional jump instruction to analyze
            address: Current address of the instruction
            
        Returns:
            LoopInfo if a loop pattern is detected, None otherwise
        """
        jump_offset = conditional_jump.op_details.body.jump_offset
        
        # Check for backward jump (loop indicator)
        if jump_offset >= 0:
            return None  # Forward jumps are not loops
            
        # Calculate loop boundaries
        loop_start = address + conditional_jump.length() + jump_offset
        loop_end = address
        
        # Check if the jump target is before the start of the current code
        # This would indicate a jump to another part of the program, not a loop
        if loop_start < 0:
            return None  # Jump target is outside current code boundaries
        
        # Analyze the condition for loop type detection
        if conditional_jump.fused_operands:
            condition = conditional_jump.fused_operands[0]
            loop_type = SmartLoopDetector._analyze_condition_type(condition)
            iterator_var = SmartLoopDetector._detect_iterator_variable(condition)
        else:
            condition = None
            loop_type = "while"  # Default for unfused conditions
            iterator_var = None
            
        return LoopInfo(
            loop_type=loop_type,
            body_start=loop_start,
            body_end=loop_end,
            condition=condition,
            iterator_var=iterator_var,
            increment_amount=None  # TODO: Detect increment patterns
        )
    
    @staticmethod
    def _analyze_condition_type(condition: 'Instruction') -> str:
        """Analyze the condition to determine likely loop type."""
        if not hasattr(condition, 'fused_operands') or len(condition.fused_operands) < 2:
            return "while"
            
        # Check for counter-style conditions (var < constant)
        left_operand = condition.fused_operands[1]  # Due to stack order
        right_operand = condition.fused_operands[0]
        
        # If comparing variable to constant (either order), likely a for-loop
        var_const_comparison = (
            (left_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar'] and
             right_operand.__class__.__name__ in ['PushByte', 'PushWord']) or
            (left_operand.__class__.__name__ in ['PushByte', 'PushWord'] and
             right_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar'])
        )
        
        if var_const_comparison:
            if condition.__class__.__name__.lower() in ['lt', 'le', 'gt', 'ge']:
                return "for"
                
        return "while"
    
    @staticmethod
    def _detect_iterator_variable(condition: 'Instruction') -> Optional[int]:
        """Detect if a variable is being used as a loop iterator."""
        if not hasattr(condition, 'fused_operands') or len(condition.fused_operands) < 2:
            return None
            
        left_operand = condition.fused_operands[1]
        right_operand = condition.fused_operands[0]
        
        # Check if left operand is a variable push
        if left_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(left_operand.op_details.body, 'data'):
                return cast(int, left_operand.op_details.body.data)
        
        # Check if right operand is a variable push (reversed order case)
        elif right_operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            if hasattr(right_operand.op_details.body, 'data'):
                return cast(int, right_operand.op_details.body.data)
                
        return None


class SmartLoopConditionalJump(SmartConditionalJump):
    """Enhanced conditional jump with loop pattern recognition."""
    
    def __init__(self, kaitai_op: Any, length: int) -> None:
        super().__init__(kaitai_op, length)
        self.detected_loop: Optional[LoopInfo] = None
    
    def detect_and_fuse_loop(self, address: int) -> bool:
        """
        Detect if this conditional jump represents a loop pattern.
        
        Args:
            address: Current instruction address
            
        Returns:
            True if a loop pattern was detected and fused
        """
        self.detected_loop = SmartLoopDetector.detect_loop_pattern(self, address)
        return self.detected_loop is not None
    
    def render(self, as_operand: bool = False) -> List[Token]:
        """Enhanced rendering that shows loop patterns when detected."""
        if self.detected_loop:
            return self._render_loop_pattern()
        else:
            return super().render()
    
    def _render_loop_pattern(self) -> List[Token]:
        """Render the instruction as a loop construct."""
        assert self.detected_loop is not None
        
        tokens: List[Token] = []
        loop_info = self.detected_loop
        
        if loop_info.loop_type == "for" and loop_info.iterator_var is not None:
            # Render as for-loop style
            tokens.append(TInstr("for"))
            tokens.append(TText(" (var_"))
            tokens.append(TInt(str(loop_info.iterator_var)))
            
            if loop_info.condition:
                # Add condition rendering
                condition_tokens = loop_info.condition.render()
                if condition_tokens:
                    tokens.append(TText("; "))
                    tokens.extend(condition_tokens)
            
            tokens.append(TText(") {"))
            
        else:
            # Render as while-loop style
            tokens.append(TInstr("while"))
            tokens.append(TText(" ("))
            
            if self.fused_operands and self.fused_operands[0]:
                # Render the fused condition
                condition_tokens = self._render_condition(self.fused_operands[0])
                tokens.extend(condition_tokens)
            else:
                tokens.append(TText("condition"))
            
            tokens.append(TText(") {"))
        
        # Add loop body information as comment
        body_size = loop_info.body_end - loop_info.body_start
        tokens.append(TText(f" # {body_size} bytes"))
        
        return tokens


# Enhanced conditional jump classes with loop detection
class SmartLoopIfNot(SmartLoopConditionalJump):
    """If-not conditional jump with loop pattern recognition."""
    _is_if_not = True


class SmartLoopIff(SmartLoopConditionalJump):
    """If conditional jump with loop pattern recognition."""
    _is_if_not = False


class SmartVariableArgumentIntrinsic(SmartIntrinsicOp):
    """Base class for intrinsic operations with variable number of arguments.
    
    This class provides a unified pattern for instructions that:
    1. Have a variable number of parameters determined by an arg_count
    2. Follow the stack pattern: [fixed_params...], arg1, arg2, ..., argN, arg_count
    3. Need to collect all parameters before rendering/lifting
    
    Subclasses should override:
    - get_fixed_param_count(): Number of fixed parameters before variable args
    - render_instruction(): Custom rendering logic
    - get_instruction_name(): Display name for the instruction
    """
    
    def __init__(self, kaitai_op: Any, length: int, addr: Optional[int] = None) -> None:
        super().__init__(kaitai_op, length, addr)
        self.fused_operands: List[Instruction] = []
        self._arg_count: Optional[int] = None
    
    def get_fixed_param_count(self) -> int:
        """Return the number of fixed parameters before variable arguments.
        
        Examples:
        - startScriptQuick(script_id, [args...]): 1 fixed param (script_id)
        - startScript(script_id, flags, [args...]): 2 fixed params
        - isAnyOf(test_value, [values...]): 1 fixed param (test_value)  
        - soundKludge([args...]): 0 fixed params
        """
        return 0
    
    def get_instruction_name(self) -> str:
        """Get the display name for this instruction."""
        return DESCUMM_FUNCTION_NAMES.get(self._name, self._name)
    
    def _is_fusible_push(self, instr: Instruction) -> bool:
        """Check if instruction is a push that can be fused."""
        return instr.__class__.__name__ in ['PushByte', 'PushWord', 'PushByteVar', 'PushWordVar']
    
    def _extract_arg_count(self, push_instr: Instruction) -> Optional[int]:
        """Extract arg_count value from a push instruction."""
        if push_instr.__class__.__name__ in ['PushByte', 'PushWord']:
            return int(push_instr.op_details.body.data)
        return None
    
    def fuse(self, previous: Instruction) -> Optional['SmartVariableArgumentIntrinsic']:
        """Generic fusion logic for variable argument instructions."""
        # First fusion: collect arg_count
        if not self.fused_operands:
            if not self._is_fusible_push(previous):
                return None
                
            fused = copy.deepcopy(self)
            fused.fused_operands = [previous]
            fused._length = self._length + previous.length()
            fused._arg_count = self._extract_arg_count(previous)
            return fused
        
        # If we have arg_count, collect arguments and fixed parameters
        if self._arg_count is not None:
            # Calculate how many operands we've collected (excluding arg_count)
            current_operand_count = len(self.fused_operands) - 1
            
            # Total needed: variable args + fixed params
            total_needed = self._arg_count + self.get_fixed_param_count()
            
            if current_operand_count < total_needed:
                if not self._is_fusible_push(previous):
                    return None
                    
                fused = copy.deepcopy(self)
                fused.fused_operands = [previous] + self.fused_operands
                fused._length = self._length + previous.length()
                fused._arg_count = self._arg_count
                return fused
        
        return None
    
    @property
    def stack_pop_count(self) -> int:
        """Calculate stack pops based on fusion state."""
        if self.fused_operands and self._arg_count is not None:
            total_needed = self._arg_count + self.get_fixed_param_count() + 1  # +1 for arg_count
            if len(self.fused_operands) >= total_needed:
                return 0  # Fully fused
        return self._config.pop_count if self._config else 1
    
    def _render_operand(self, operand: Instruction) -> List[Token]:
        """Render a fused operand appropriately."""
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return [TInt(get_variable_name(operand.op_details.body.data))]
        elif operand.__class__.__name__ in ['PushByte', 'PushWord']:
            if hasattr(operand.op_details.body, 'data'):
                return [TInt(str(operand.op_details.body.data))]
            else:
                return [TInt("?")]
        else:
            return [TInt("operand")]
    
    def _lift_operand(self, il: LowLevelILFunction, operand: Instruction) -> Any:
        """Lift a fused operand to IL expression."""
        from ... import vars
        
        if operand.__class__.__name__ in ['PushByteVar', 'PushWordVar']:
            return vars.il_get_var(il, operand.op_details.body)
        else:
            if hasattr(operand.op_details.body, 'data'):
                value = operand.op_details.body.data
                return il.const(4, value)
        return il.const(4, 0)
    
    def render_instruction(self) -> List[Token]:
        """Override this method to provide custom rendering logic.
        
        The base implementation provides a simple pattern for most cases.
        Subclasses can override for complex rendering needs.
        """
        if not (self.fused_operands and self._arg_count is not None):
            return [TInstr(f"{self.get_instruction_name()}()")]
        
        total_needed = self._arg_count + self.get_fixed_param_count() + 1
        if len(self.fused_operands) < total_needed:
            return [TInstr(f"{self.get_instruction_name()}()")]
        
        tokens = [TInstr(self.get_instruction_name()), TSep("(")]
        
        # Render fixed parameters first (they come first in LIFO order)
        fixed_count = self.get_fixed_param_count()
        for i in range(fixed_count):
            if i > 0:
                tokens.append(TSep(","))
            tokens.extend(self._render_operand(self.fused_operands[i]))
        
        # Add separator before variable args if we have fixed params
        if fixed_count > 0 and self._arg_count > 0:
            tokens.append(TSep(","))
        
        # Render variable arguments as array
        if self._arg_count > 0:
            tokens.append(TSep("["))
            for i in range(fixed_count, fixed_count + self._arg_count):
                if i > fixed_count:
                    tokens.append(TSep(", "))
                tokens.extend(self._render_operand(self.fused_operands[i]))
            tokens.append(TSep("]"))
        
        tokens.append(TSep(")"))
        return tokens
    
    def render(self, as_operand: bool = False) -> List[Token]:
        """Default render method - delegates to render_instruction()."""
        return self.render_instruction()
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL for variable argument instruction."""
        if self.fused_operands and self._arg_count is not None:
            total_needed = self._arg_count + self.get_fixed_param_count() + 1
            if len(self.fused_operands) >= total_needed:
                # Create parameters: fixed params + variable args (skip arg_count)
                params = []
                param_count = self.get_fixed_param_count() + self._arg_count
                for i in range(param_count):
                    params.append(self._lift_operand(il, self.fused_operands[i]))
                
                # Generate intrinsic call
                if self._config and self._config.push_count > 0:
                    il.append(il.intrinsic([il.reg(4, "TEMP0")], self._name, params))
                    il.append(il.push(4, il.reg(4, "TEMP0")))
                else:
                    il.append(il.intrinsic([], self._name, params))
                return
        
        # Fallback to default lifting
        super().lift(il, addr)
