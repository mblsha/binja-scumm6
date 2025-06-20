"""Smart base classes for generated instruction types."""

from typing import List, Optional

try:
    from binja_helpers.tokens import Token, TInstr, TSep, TInt
    from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
    from binaryninja import InstructionInfo, BranchType
    BINJA_AVAILABLE = True
except ImportError:
    # Handle case where Binary Ninja is not available (e.g., in tests)
    BINJA_AVAILABLE = False
    # Define minimal stubs for type checking
    class InstructionInfo:  # type: ignore[no-redef]
        def __init__(self) -> None:
            self.length = 0
            self.add_branch = lambda *args: None
    
    class BranchType:  # type: ignore[no-redef]
        CallDestination = "CallDestination"
        IndirectBranch = "IndirectBranch"
        FunctionReturn = "FunctionReturn"
    
    class Token:  # type: ignore[no-redef]
        pass
    
    class TInstr(Token):  # type: ignore[no-redef]
        def __init__(self, name: str) -> None: pass
    
    class TSep(Token):  # type: ignore[no-redef]
        def __init__(self, sep: str) -> None: pass
    
    class TInt(Token):  # type: ignore[no-redef]
        def __init__(self, value: int) -> None: pass
    
    class LowLevelILFunction:  # type: ignore[no-redef]
        pass
    
    def LLIL_TEMP(n: int) -> int:
        return n

from .opcodes import Instruction
from .configs import (IntrinsicConfig, VariableConfig, ArrayConfig, ComplexConfig, StackConfig,
                     SemanticIntrinsicConfig)
from ...scumm6_opcodes import Scumm6Opcodes

class SmartIntrinsicOp(Instruction):
    """Self-configuring intrinsic operation base class."""
    
    _name: str
    _config: IntrinsicConfig
    
    def render(self) -> List[Token]:
        return [TInstr(self._name)]
    
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
            outputs = [il.reg(4, LLIL_TEMP(i)) for i in range(self._config.push_count)]
            il.append(il.intrinsic(outputs, self._name, params))
            for out_reg in outputs:
                il.append(il.push(4, out_reg))
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

class SmartVariableOp(Instruction):
    """Self-configuring variable operation base class."""
    
    _name: str
    _config: VariableConfig
    
    def render(self) -> List[Token]:
        var_id = self.op_details.body.data
        return [
            TInstr(self._name),
            TSep("("),
            TInt(f"var_{var_id}"),
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

class SmartComplexOp(Instruction):
    """Unified complex operation handler."""
    
    _name: str
    _config: ComplexConfig
    
    def render(self) -> List[Token]:
        subop_name = self.op_details.body.subop.name
        return [TInstr(f"{self._name}.{subop_name}")]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        from ...scumm6_opcodes import Scumm6Opcodes
        
        # Get the expected body type dynamically
        expected_type = getattr(Scumm6Opcodes, self._config.body_type_name)
        assert isinstance(self.op_details.body, expected_type), \
            f"Expected {expected_type.__name__} body, got {type(self.op_details.body)}"
        
        # Access the subop and its body
        subop = self.op_details.body.subop
        subop_body = self.op_details.body.body
        
        # Construct intrinsic name
        intrinsic_name = f"{self._name}.{subop.name}"
        
        # Handle parameters based on subop_body attributes
        pop_count = getattr(subop_body, "pop_count", 0)
        push_count = getattr(subop_body, "push_count", 0)
        
        # Pop arguments and call intrinsic
        params = [il.pop(4) for _ in range(pop_count)]
        
        if push_count > 0:
            il.append(il.intrinsic([il.reg(4, LLIL_TEMP(0))], intrinsic_name, params))
            il.append(il.push(4, il.reg(4, LLIL_TEMP(0))))
        else:
            il.append(il.intrinsic([], intrinsic_name, params))

# Smart stack operation base classes
class SmartBinaryOp(Instruction):
    """Self-configuring binary stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop two values: a (top), b (second)
        il.append(il.set_reg(4, LLIL_TEMP(0), il.pop(4)))  # a
        il.append(il.set_reg(4, LLIL_TEMP(1), il.pop(4)))  # b

        # Get the operation from the il object
        il_func = getattr(il, self._config.il_op_name)

        # Push result: b op a
        op1 = il.reg(4, LLIL_TEMP(1))
        op2 = il.reg(4, LLIL_TEMP(0))
        result = il_func(4, op1, op2)
        il.append(il.push(4, result))

class SmartUnaryOp(Instruction):
    """Self-configuring unary stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
        # Pop one value
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

class SmartComparisonOp(Instruction):
    """Self-configuring comparison stack operation."""
    
    _name: str
    _config: StackConfig
    
    def render(self) -> List[Token]:
        display_name = self._config.display_name or self._name
        return [TInstr(display_name)]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        assert isinstance(self.op_details.body, Scumm6Opcodes.NoData), \
            f"Expected NoData body, got {type(self.op_details.body)}"
        
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
    
    def render(self) -> List[Token]:
        if hasattr(self.op_details.body, 'array'):
            array_id = self.op_details.body.array
            return [
                TInstr(self._name),
                TSep("("),
                TInt(f"array_{array_id}"),
                TSep(")"),
            ]
        else:
            return [TInstr(self._name)]
    
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

class SmartSemanticIntrinsicOp(Instruction):
    """Self-configuring semantic intrinsic following descumm philosophy."""
    
    _name: str
    _config: SemanticIntrinsicConfig
    
    def render(self) -> List[Token]:
        """Render in descumm-style function call format."""
        return self._render_semantic_call()
    
    def _render_semantic_call(self) -> List[Token]:
        """Render as: semantic_name(param1, param2, ...)"""
        tokens = [TInstr(self._config.semantic_name), TSep("(")]
        
        # For variable args operations, show dynamic parameter count
        if self._config.variable_args:
            # Show script_id as first param, then variable args indicator
            if self._config.parameter_names:
                first_param = self._config.parameter_names[0]
                tokens.extend([TInstr(first_param)])
                if len(self._config.parameter_names) > 1:
                    tokens.extend([TSep(","), TSep(" "), TInstr("...")])
            else:
                tokens.append(TInstr("..."))
        else:
            # Show fixed parameters
            for i, param_name in enumerate(self._config.parameter_names):
                if i > 0:
                    tokens.extend([TSep(","), TSep(" ")])
                tokens.append(TInstr(param_name))
        
        tokens.append(TSep(")"))
        return tokens
    
    def analyze(self, info: InstructionInfo, addr: int) -> None:
        """Set instruction analysis info, including control flow branches."""
        # Always call parent to set basic info like length
        super().analyze(info, addr)
        
        # Handle control flow implications if configured
        if self._config.control_flow_impact:
            self._handle_control_flow_analysis(info, addr)
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL following descumm semantic approach."""
        # Handle variable arguments for script operations
        if self._config.variable_args:
            self._lift_variable_args_operation(il, addr)
        else:
            self._lift_fixed_args_operation(il, addr)
    
    def _lift_variable_args_operation(self, il: LowLevelILFunction, addr: int) -> None:
        """Handle operations with variable arguments (like start_script)."""
        # Extract variable arguments first (following original scumm6.py pattern)
        args = self._extract_variable_arguments(il)
        
        # Get the main parameters (script_id for script operations)
        script_id = il.pop(4)
        params = [script_id] + args
        
        # For start_script, also handle flags
        if self._name == "start_script":
            flags = il.pop(4)
            params = [script_id, flags] + args
        
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
    
    def _handle_control_flow_analysis(self, info: InstructionInfo, addr: int) -> None:
        """Handle control flow analysis for semantic intrinsic operations."""
        if not BINJA_AVAILABLE:
            # Skip control flow analysis when Binary Ninja is not available (e.g., in tests)
            return
            
        try:
            # For script operations like start_script, the script ID comes from the stack
            # and isn't available during the analyze phase. However, we can still mark
            # this as a call instruction to indicate control flow impact.
            
            # Try to extract and resolve script ID if possible
            script_id = self._extract_script_id()
            script_addr = None
            
            if script_id is not None:
                script_addr = self._resolve_script_address(script_id, addr)
            
            if script_addr is not None:
                # We successfully resolved the script address
                info.add_branch(BranchType.CallDestination, script_addr)
            else:
                # We couldn't resolve the exact address, but we know this is a call
                # Mark it as an indirect call to indicate control flow impact
                # Binary Ninja will handle this appropriately during analysis
                info.add_branch(BranchType.IndirectBranch, 0)
            
            # Always add fall-through branch (execution continues after the call)
            info.add_branch(BranchType.FalseBranch, addr + info.length)
            
        except Exception:
            # If anything goes wrong, don't crash the analysis
            # Just skip the control flow analysis for this instruction
            pass
    
    def _extract_script_id(self) -> Optional[int]:
        """Extract script ID from the instruction operands."""
        try:
            # For script operations like start_script, the script ID comes from the stack
            # and isn't directly embedded in the instruction. During the analyze phase,
            # we don't have access to the runtime stack state.
            
            # Check if the instruction has any embedded data that might be a script ID
            if hasattr(self.op_details, 'body') and hasattr(self.op_details.body, 'data'):
                # For simple script operations, script ID might be directly in data
                data = self.op_details.body.data
                return int(data) if isinstance(data, (int, float)) else None
            elif hasattr(self.op_details, 'body') and hasattr(self.op_details.body, 'script_id'):
                # Some instructions might have a dedicated script_id field
                script_id = self.op_details.body.script_id
                return int(script_id) if isinstance(script_id, (int, float)) else None
            else:
                # For stack-based operations like start_script, we can't extract the script ID
                # during the analyze phase. This is expected and not an error.
                return None
        except Exception:
            return None
    
    def _resolve_script_address(self, script_id: int, call_addr: int) -> Optional[int]:
        """Resolve script ID to actual address using the disasm state."""
        try:
            # Import here to avoid circular imports
            from ...scumm6 import LastBV
            from ...disasm import Scumm6Disasm
            
            # Get the current binary view and its state
            view = LastBV.get()
            if view is None or not hasattr(view, 'state'):
                return None
            
            state = view.state
            
            # Use the legacy get_script_ptr function to resolve the address
            return Scumm6Disasm.get_script_ptr(state, script_id, call_addr)
            
        except Exception:
            return None
    
    def _handle_script_call_flow(self, il: LowLevelILFunction, script_id: int) -> None:
        """Handle control flow implications for script calls in LLIL."""
        # This method is used during LLIL lifting, not analysis
        # The actual control flow analysis is now handled in _handle_control_flow_analysis
        # This method could be enhanced to generate call instructions in LLIL if needed
        pass
