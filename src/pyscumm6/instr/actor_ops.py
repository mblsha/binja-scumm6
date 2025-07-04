"""Actor-related intrinsic operations with special LLIL handling."""

from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from binaryninja import IntrinsicName

from .smart_bases import SmartFusibleIntrinsic
from ...actor_state import ACTORS_START, ACTOR_STRUCT_SIZE


class ActorIntrinsic(SmartFusibleIntrinsic):
    """Base class for actor-related intrinsics that need actor address calculation."""
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Lift the instruction, converting actor index to actor struct address."""
        if self.fused_operands:
            # Build parameters from fused operands
            params = []
            
            # First parameter is actor index - convert to actor struct address
            if len(self.fused_operands) > 0:
                actor_index = self._lift_operand(il, self.fused_operands[0])
                
                # Calculate actor struct address: ACTORS_START + (index * ACTOR_STRUCT_SIZE)
                actor_addr = il.add(4,
                    il.const_pointer(4, ACTORS_START),
                    il.mult(4, actor_index, il.const(4, ACTOR_STRUCT_SIZE))
                )
                params.append(actor_addr)
                
                # Add remaining fused operands as-is
                for operand in self.fused_operands[1:]:
                    params.append(self._lift_operand(il, operand))
            
            # Add any remaining stack pops if we don't have all operands fused
            remaining_pops = self._config.pop_count - len(self.fused_operands)
            for i in range(remaining_pops):
                if i == 0 and len(params) == 0:
                    # First parameter - convert from index to address
                    actor_index = il.pop(4)
                    actor_addr = il.add(4,
                        il.const_pointer(4, ACTORS_START),
                        il.mult(4, actor_index, il.const(4, ACTOR_STRUCT_SIZE))
                    )
                    params.append(actor_addr)
                else:
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
            # No fusion - pop actor index from stack and convert to address
            actor_index = il.pop(4)
            actor_addr = il.add(4,
                il.const_pointer(4, ACTORS_START),
                il.mult(4, actor_index, il.const(4, ACTOR_STRUCT_SIZE))
            )
            
            # Pop remaining parameters
            params = [actor_addr]
            for _ in range(1, self._config.pop_count):
                params.append(il.pop(4))
            
            # Generate the intrinsic call
            if self._config.push_count > 0:
                output_regs = [LLIL_TEMP(i) for i in range(self._config.push_count)]
                il.append(il.intrinsic(output_regs, IntrinsicName(self._name), params))
                for reg in output_regs:
                    il.append(il.push(4, il.reg(4, reg)))
            else:
                il.append(il.intrinsic([], IntrinsicName(self._name), params))


class PutActorAtXy(ActorIntrinsic):
    """Put actor at specific coordinates."""
    _name = "put_actor_at_xy"


class AnimateActor(ActorIntrinsic):
    """Animate actor with specified animation."""
    _name = "animate_actor"