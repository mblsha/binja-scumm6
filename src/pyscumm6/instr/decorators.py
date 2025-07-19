"""Decorators and mixins for instruction classes.

This module provides decorators and mixins to reduce code duplication
across instruction classes while maintaining the same behavior.
"""

from typing import Any, Callable, Optional, List, TYPE_CHECKING, TypeVar, cast
from functools import wraps

if TYPE_CHECKING:
    from .opcodes import Instruction
    from binja_test_mocks.tokens import Token
    from binaryninja.lowlevelil import LowLevelILFunction

T = TypeVar('T')


def with_descumm_name_mapping(render_method: Callable[..., List['Token']]) -> Callable[..., List['Token']]:
    """
    Decorator to automatically apply descumm function name mapping to render methods.
    
    This decorator intercepts the render method, applies the name mapping,
    and modifies the first token if it's an instruction name.
    """
    @wraps(render_method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> List['Token']:
        from .helpers import apply_descumm_function_name
        from binja_test_mocks.tokens import TInstr
        
        # Get the original tokens
        tokens = render_method(self, *args, **kwargs)
        
        # If the first token is an instruction, apply mapping
        if tokens and hasattr(tokens[0], '__class__') and tokens[0].__class__.__name__ == 'InstructionTextToken':
            # Extract the text from the first token
            original_text = str(tokens[0].text if hasattr(tokens[0], 'text') else tokens[0])
            
            # Check if it contains parentheses (function call style)
            if '(' in original_text:
                # Extract just the function name part
                func_name = original_text.split('(')[0]
                rest = original_text[len(func_name):]
                
                # Apply mapping to the function name
                mapped_name = apply_descumm_function_name(func_name)
                
                # Create new token with mapped name
                tokens[0] = TInstr(mapped_name + rest)
        
        return tokens
    
    return wrapper


def with_fusion_support(cls: type[T]) -> type[T]:
    """
    Class decorator to add standard fusion support to an instruction class.
    
    This decorator adds a fuse() method that uses the standard fusion logic
    from FusibleMultiOperandMixin.
    """
    # Check if the class already has fusion support
    if hasattr(cls, 'fuse') and not hasattr(cls, '_fusion_added_by_decorator'):
        return cls
    
    def fuse(self: Any, previous: 'Instruction') -> Optional['Instruction']:
        """Attempt to fuse with the previous instruction using standard fusion logic."""
        # Use the mixin's standard fusion logic if available
        if hasattr(self, '_standard_fuse'):
            return cast(Optional['Instruction'], self._standard_fuse(previous))
        return None
    
    # Add the fuse method and mark it
    cls.fuse = fuse  # type: ignore[attr-defined]
    cls._fusion_added_by_decorator = True  # type: ignore[attr-defined]
    
    return cls


def with_stack_count_property(pop_count_attr: str = '_config.pop_count') -> Callable[[type[T]], type[T]]:
    """
    Class decorator to add standard stack_pop_count property.
    
    Args:
        pop_count_attr: The attribute path to get the base pop count from
    """
    def decorator(cls: type[T]) -> type[T]:
        def stack_pop_count_getter(self: Any) -> int:
            """Number of values this instruction pops from the stack."""
            # Get the base pop count
            if '.' in pop_count_attr:
                obj = self
                for attr in pop_count_attr.split('.'):
                    obj = getattr(obj, attr, 0)
                base_pop_count = obj
            else:
                base_pop_count = getattr(self, pop_count_attr, 0)
            
            # If we have fused operands, we pop fewer from the stack
            if hasattr(self, 'fused_operands'):
                return max(0, int(base_pop_count) - len(self.fused_operands))
            return int(base_pop_count)
        
        # Create property and add to class
        cls.stack_pop_count = property(stack_pop_count_getter)  # type: ignore[attr-defined]
        return cls
    
    return decorator


class OperandRenderingMixin:
    """Mixin providing shared operand rendering functionality."""
    
    def _render_operand(self, operand: 'Instruction') -> List['Token']:
        """Render a fused operand appropriately."""
        from .helpers import render_operand
        return render_operand(operand)
    
    def _render_operand_with_parens(self, operand: 'Instruction') -> List['Token']:
        """Render a fused operand with parentheses for nested expressions."""
        from .helpers import render_operand_with_parens
        return render_operand_with_parens(operand)
    
    def _render_operand_smart_binary(self, operand: 'Instruction', as_operand: bool = False) -> List['Token']:
        """Render a fused operand for binary operations with special parentheses handling."""
        from .helpers import render_operand_smart_binary
        return render_operand_smart_binary(operand, as_operand)


class OperandLiftingMixin:
    """Mixin providing shared operand lifting functionality."""
    
    def _lift_operand(self, il: 'LowLevelILFunction', operand: 'Instruction') -> Any:
        """Lift a fused operand to IL expression."""
        from .helpers import lift_operand
        return lift_operand(il, operand)


class StandardStackPopMixin:
    """Mixin providing standard stack pop count behavior."""
    
    @property
    def stack_pop_count(self) -> int:
        """Number of values this instruction pops from the stack."""
        # Default implementation - can be overridden
        if hasattr(self, '_config') and hasattr(self._config, 'pop_count'):
            base_count = self._config.pop_count
        else:
            base_count = 0
        
        # If we have fused operands, we pop fewer from the stack
        if hasattr(self, 'fused_operands'):
            return max(0, int(base_count) - len(self.fused_operands))
        return int(base_count)


class ProducesResultMixin:
    """Mixin for instructions that produce results."""
    
    def produces_result(self) -> bool:
        """Check if this instruction produces a result that can be consumed by other instructions."""
        # Default implementation based on push_count
        if hasattr(self, '_config') and hasattr(self._config, 'push_count'):
            return bool(self._config.push_count > 0)
        return True  # Conservative default for operations


class FusiblePushMixin:
    """Mixin providing a shared _is_fusible_push implementation."""

    def _is_fusible_push(self, instr: 'Instruction') -> bool:
        from .helpers import is_fusible_push

        return is_fusible_push(instr)
