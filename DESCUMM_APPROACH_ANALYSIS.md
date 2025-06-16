# SCUMM6 Descumm-Inspired Implementation Strategy

## 🎯 **Philosophy: Semantic Clarity for Reverse Engineering**

Based on analysis of scummvm-tools descumm, the optimal approach for implementing unimplemented SCUMM6 instructions prioritizes **semantic clarity over implementation details** to maximize reverse engineering effectiveness.

## 📋 **Descumm's Core Principles**

### 1. **Function-Call Representation**
- **What**: Transform bytecode into readable function calls
- **Example**: `startScript(scriptId, flags)` instead of stack manipulation
- **LLIL Approach**: Use intrinsics with descriptive names

### 2. **Parameter Clarity**
- **What**: Show parameters in context of their purpose
- **Example**: `walkActorTo(actor=1, x=100, y=50)` 
- **LLIL Approach**: Use meaningful parameter names in intrinsic signatures

### 3. **Semantic Abstraction**
- **What**: Hide low-level implementation, show game logic intent
- **Example**: `ActorOps(actor, [Costume(id), WalkSpeed(speed)])` 
- **LLIL Approach**: Complex operations as semantic intrinsics

### 4. **Human-Readable Domain Language**
- **What**: Use game engine terminology, not technical jargon
- **Example**: `setObjectName(objectId, "name")` not `memory_store(addr, data)`
- **LLIL Approach**: Game-domain intrinsic names

## 🔍 **Current Unimplemented Instructions Analysis**

### **Primary Targets (Confirmed Unimplemented)**
1. **`start_script` (94)** - Start script with flags
2. **`start_script_quick` (95)** - Start script without flags  
3. **`start_script_quick2` (191)** - Start script quick variant 2

### **Secondary Targets (Could Be Enhanced)**
- Instructions currently using basic intrinsics that could benefit from descumm-style representation
- Complex operations that show low-level details instead of semantic meaning

## 🏗️ **Implementation Strategy**

### **Phase 1: Semantic Intrinsic Design**

#### **A. Enhanced Configuration System**
```python
@dataclass
class SemanticIntrinsicConfig(IntrinsicConfig):
    """Configuration for semantically-rich intrinsics following descumm approach."""
    semantic_name: str              # Game-domain name (e.g., "start_script")
    parameter_names: List[str]      # Meaningful parameter names
    return_description: str = ""    # What the operation returns
    side_effects: List[str] = field(default_factory=list)  # What it affects
    control_flow_impact: bool = False  # Whether it affects control flow
    show_data_flow: bool = True     # Whether to show stack operations
    
# Example configurations
SEMANTIC_CONFIGS = {
    "start_script": SemanticIntrinsicConfig(
        semantic_name="start_script",
        parameter_names=["script_id", "flags", "*args"],
        pop_count=0,  # Variable based on args
        push_count=0,
        side_effects=["launches_new_script", "may_change_game_state"],
        control_flow_impact=True,
        doc="Start script execution with optional flags and arguments"
    ),
}
```

#### **B. Smart Semantic Base Class**
```python
class SmartSemanticIntrinsicOp(Instruction):
    """Base class for semantically-rich operations following descumm approach."""
    
    _semantic_config: SemanticIntrinsicConfig
    
    def render(self) -> List[Token]:
        """Render in descumm-style function call format."""
        return self._render_semantic_call()
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        """Generate LLIL that balances data flow with semantic clarity."""
        if self._semantic_config.show_data_flow:
            self._lift_data_operations(il, addr)
        
        self._lift_semantic_intrinsic(il, addr)
        
        if self._semantic_config.control_flow_impact:
            self._handle_control_flow_effects(il, addr)
    
    def _render_semantic_call(self) -> List[Token]:
        """Render as: semantic_name(param1=value1, param2=value2)"""
        tokens = [TInstr(self._semantic_config.semantic_name), TSep("(")]
        
        # Add parameters with semantic names
        for i, param_name in enumerate(self._semantic_config.parameter_names):
            if i > 0:
                tokens.extend([TSep(","), TSep(" ")])
            tokens.extend([
                TInstr(param_name), TSep("="), 
                self._get_parameter_token(i)
            ])
        
        tokens.append(TSep(")"))
        return tokens
```

### **Phase 2: Start Script Implementation Example**

#### **Following Descumm Philosophy**
```python
class StartScript(SmartSemanticIntrinsicOp):
    """
    Descumm representation: startScript(scriptId, flags, arg1, arg2, ...)
    LLIL representation: Semantic intrinsic + control flow handling
    """
    
    _semantic_config = SEMANTIC_CONFIGS["start_script"]
    
    def lift(self, il: LowLevelILFunction, addr: int) -> None:
        # Step 1: Extract arguments (following original implementation pattern)
        args = self._extract_variable_arguments(il)
        script_id = il.pop(4)
        
        if self.op_details.id == OpType.start_script:
            flags = il.pop(4)
            params = [script_id, flags] + args
            intrinsic_name = "start_script"
        else:
            params = [script_id] + args
            intrinsic_name = "start_script_quick"
        
        # Step 2: Generate semantic intrinsic (descumm-style)
        il.append(il.intrinsic([], intrinsic_name, params))
        
        # Step 3: Handle control flow implications
        # This is where we'd resolve script addresses for CFG analysis
        if self._can_resolve_script_address(script_id):
            target_addr = self._resolve_script_address(script_id)
            il.append(il.call(il.const_pointer(4, target_addr)))
```

### **Phase 3: Enhanced Rendering for Reverse Engineering**

#### **Multi-Level Representation**
```python
class AnalysisAwareIntrinsic(SmartSemanticIntrinsicOp):
    """Provides different representations based on analysis context."""
    
    def render(self) -> List[Token]:
        """Primary rendering: Descumm-style semantic representation."""
        return self._render_semantic_call()
    
    def render_detailed(self) -> List[Token]:
        """Detailed rendering: Show data flow + semantics."""
        tokens = []
        
        # Show the data operations
        tokens.extend([TInstr("// Data flow:"), TSep(" ")])
        tokens.extend(self._render_stack_operations())
        tokens.append(TSep("\\n"))
        
        # Show the semantic operation
        tokens.extend(self._render_semantic_call())
        
        return tokens
    
    def render_technical(self) -> List[Token]:
        """Technical rendering: Full implementation details."""
        return self._render_llil_operations()
```

### **Phase 4: Context-Aware Documentation**

#### **Reverse Engineering Focused Documentation**
```python
@dataclass
class ReverseEngineeringDoc:
    """Documentation optimized for reverse engineering workflows."""
    semantic_description: str      # What it does in game terms
    parameters: Dict[str, str]     # Parameter meanings
    side_effects: List[str]        # What changes in the game
    common_patterns: List[str]     # Typical usage patterns  
    analysis_tips: List[str]       # How to analyze in Binary Ninja

RE_DOCS = {
    "start_script": ReverseEngineeringDoc(
        semantic_description="Launches a new SCUMM script for execution",
        parameters={
            "script_id": "Numeric ID of the script to start",
            "flags": "Execution flags (bit 0: freeze_resistant, bit 1: recursive)",
            "*args": "Variable arguments passed to the script"
        },
        side_effects=[
            "Creates new script execution context",
            "May modify global game variables",
            "Can trigger other scripts through script interactions"
        ],
        common_patterns=[
            "start_script(5, 0) - Start script 5 with no flags",
            "start_script(10, 2, param1, param2) - Start script 10 recursively with parameters"
        ],
        analysis_tips=[
            "Check script_id for cross-references to understand script relationships",
            "Monitor flags to understand execution priority and interruption behavior",
            "Track arguments to understand data flow between scripts"
        ]
    )
}
```

## 🎮 **Game-Semantic Instruction Categories**

### **1. Script Management**
- **Semantic Names**: `start_script`, `stop_script`, `jump_to_script`
- **Focus**: Script lifecycle and execution flow
- **LLIL Approach**: Control flow intrinsics with CFG integration

### **2. Actor Operations**  
- **Semantic Names**: `walk_actor_to`, `set_actor_costume`, `get_actor_position`
- **Focus**: Character behavior and state
- **LLIL Approach**: State modification intrinsics

### **3. Object Manipulation**
- **Semantic Names**: `draw_object`, `hide_object`, `set_object_state`  
- **Focus**: Game object lifecycle
- **LLIL Approach**: Object state intrinsics

### **4. Room/Environment**
- **Semantic Names**: `load_room`, `set_camera_position`, `change_room_music`
- **Focus**: Environment and scene management
- **LLIL Approach**: Environment state intrinsics

### **5. Audio/Visual Effects**
- **Semantic Names**: `play_sound`, `start_animation`, `show_cutscene`
- **Focus**: Presentation layer
- **LLIL Approach**: Effect trigger intrinsics

## 🔧 **Implementation Workflow**

### **Step 1: Analyze Current Implementation**
1. Study existing implementation in `scumm6.py`
2. Identify semantic meaning and game domain purpose
3. Extract parameter semantics and side effects

### **Step 2: Design Semantic Representation**
1. Create descumm-style function call representation
2. Design meaningful parameter names
3. Identify control flow and state implications

### **Step 3: Implement Enhanced LLIL**
1. Create semantic intrinsic with clear name
2. Generate proper data flow representation
3. Handle control flow implications for CFG

### **Step 4: Add Reverse Engineering Features**
1. Create multiple rendering modes (semantic, detailed, technical)
2. Add context-aware documentation
3. Enable cross-reference analysis

### **Step 5: Validate Against Descumm**
1. Compare semantic representation with descumm output
2. Ensure human readability and clarity
3. Validate reverse engineering workflow effectiveness

## 🎯 **Success Criteria**

### **Semantic Clarity**
- ✅ Instructions read like game logic, not bytecode
- ✅ Parameters have obvious game-domain meaning
- ✅ Side effects and implications are clear

### **Reverse Engineering Effectiveness**
- ✅ Easy to understand game logic flow
- ✅ Clear data dependencies and state changes
- ✅ Effective for finding patterns and relationships

### **Technical Accuracy**
- ✅ Preserves all original functionality
- ✅ Generates correct LLIL for analysis
- ✅ Maintains CFG and data flow accuracy

### **Developer Experience**
- ✅ Easy to add new semantic instructions
- ✅ Consistent patterns across instruction types
- ✅ Clear documentation and examples

## 🚀 **Expected Impact**

This approach will transform Binary Ninja's SCUMM6 disassembly from technical bytecode representation into **game logic documentation**, making reverse engineering significantly more effective for understanding game mechanics, finding bugs, and modifying game behavior.

The result will be LLIL that reads like commented pseudocode while maintaining all the technical accuracy needed for detailed analysis.