from typing import Dict, Any, List, Optional
from openai.types.shared_params import FunctionDefinition
import importlib
import json

from core.llm import LLMProvider
from core.scanner import Scanner
from utils.logger import get_logger

def create_agent_swarm(agent_type: str, llm_provider: LLMProvider, scanner: Scanner, config: Dict[str, Any]):
    """Factory function to create the appropriate agent swarm based on type."""
    logger = get_logger()
    logger.info(f"Creating agent swarm of type: {agent_type}")
    
    if agent_type == "security":
        # Import here to avoid circular imports
        from agents.security_swarm import SecuritySwarm
        return SecuritySwarm(llm_provider, scanner, config)
    elif agent_type == "discovery":
        from agents.discovery_swarm import DiscoverySwarm
        return DiscoverySwarm(llm_provider, scanner, config)
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")

class BaseAgent:
    """Base class for all agents."""
    
    def __init__(self, name: str, role: str, llm_provider: LLMProvider, tools: List[Dict[str, Any]]):
        self.name = name
        self.role = role
        self.llm_provider = llm_provider
        self.tools = tools
        self.logger = get_logger()
        self.memory = []
    
    def think(self, input_data: Dict[str, Any], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Process input data and generate a response with optional tool calling."""
        messages = self._prepare_messages(input_data, system_prompt)
        temperature = self._get_appropriate_temperature()
        
        # Generate response
        raw_response = self.llm_provider.chat_completion(
            messages=messages,
            temperature=temperature,
            tools=self.tools if self.tools else None
        )
        
        # Standardize response format
        response = self._standardize_response(raw_response)
        
        # Save the user message to memory
        self._update_memory_with_user_message(messages[-1]["content"])
        
        # Handle tool calls if present
        if response.get("tool_calls"):
            return self._process_tool_calls(response)
        else:
            # Regular response with no tool calls
            self.memory.append({"role": "assistant", "content": response["content"]})
            return response
    
    def _prepare_messages(self, input_data: Dict[str, Any], system_prompt: Optional[str] = None) -> List[Dict[str, Any]]:
        """Prepare the message list for the LLM request."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Add context from memory with appropriate limits
        memory_limit = 3 if self._is_ollama() else 5
        for mem in self.memory[-memory_limit:]:
            messages.append(mem)
        
        # Format and add the current input
        if isinstance(input_data, dict) and "content" in input_data:
            messages.append({"role": "user", "content": input_data["content"]})
        elif isinstance(input_data, str):
            messages.append({"role": "user", "content": input_data})
        else:
            messages.append({"role": "user", "content": f"Process the following information: {input_data}"})
            
        return messages
    
    def _is_ollama(self) -> bool:
        """Check if we're using Ollama as the provider."""
        return hasattr(self.llm_provider, 'provider') and self.llm_provider.provider == "ollama"
    
    def _is_small_model(self) -> bool:
        """Check if we're using a small model that needs special handling."""
        if not self._is_ollama() or not hasattr(self.llm_provider, 'model'):
            return False
            
        small_models = ["r1", "deepseek", "phi", "gemma", "mistral"]
        return any(model in self.llm_provider.model.lower() for model in small_models)
    
    def _get_appropriate_temperature(self) -> float:
        """Get the appropriate temperature based on the model being used."""
        if not self._is_ollama():
            return 0.7
            
        if self._is_small_model():
            self.logger.debug(f"Using low temperature (0.2) for small Ollama model: {self.llm_provider.model}")
            return 0.2
            
        return 0.5  # Default for Ollama
    
    def _standardize_response(self, raw_response: Any) -> Dict[str, Any]:
        """Standardize the response format regardless of provider."""
        response = {"content": "", "tool_calls": []}
        
        if hasattr(raw_response, 'choices') and raw_response.choices:
            first_choice = raw_response.choices[0]
            response["content"] = first_choice.message.content or ""
            if hasattr(first_choice.message, 'tool_calls') and first_choice.message.tool_calls:
                response["tool_calls"] = first_choice.message.tool_calls
        else:
            # Fallback for dictionary-style responses
            response["content"] = raw_response.get("content", "")
            response["tool_calls"] = raw_response.get("tool_calls", [])
            
        return response
    
    def _update_memory_with_user_message(self, message: str) -> None:
        """Add user message to memory if not already present."""
        if not self.memory or self.memory[-1]["role"] != "user" or self.memory[-1]["content"] != message:
            self.memory.append({"role": "user", "content": message})
    
    def _process_tool_calls(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Process tool calls, execute them, and handle follow-up responses."""
        tool_results = []
        
        # Execute each tool call
        for tool_call in response["tool_calls"]:
            result = self._execute_single_tool_call(tool_call)
            tool_results.append(result)
        
        # Store the assistant message with tool calls
        assistant_msg = self._create_assistant_message_with_tool_calls(response)
        self.memory.append(assistant_msg)
        
        # Process tool results and add to memory
        tool_messages = self._create_tool_messages(tool_results)
        for tool_msg in tool_messages:
            self.memory.append(tool_msg)
        
        # Get a follow-up response incorporating the tool results
        followup_response = self._get_followup_response()
        
        # Include the tool results and followup in the response
        response["tool_results"] = tool_results
        response["followup_response"] = followup_response
        
        return response
    
    def _execute_single_tool_call(self, tool_call: Any) -> Dict[str, Any]:
        """Execute a single tool call and return the result with metadata."""
        tool_call_id = self._get_tool_call_id(tool_call)
        tool_name = self._get_tool_call_name(tool_call)
        
        try:
            tool_result = self.execute_tool(tool_call)
            return {
                "tool_call_id": tool_call_id,
                "name": tool_name,
                "result": tool_result
            }
        except Exception as e:
            self.logger.error(f"Error executing tool: {str(e)}")
            return {
                "tool_call_id": tool_call_id,
                "name": tool_name,
                "error": str(e)
            }
    
    def _get_tool_call_id(self, tool_call: Any) -> str:
        """Safely extract the tool call ID."""
        if hasattr(tool_call, 'id'):
            return tool_call.id
        return tool_call.get('id', 'unknown_id')
    
    def _get_tool_call_name(self, tool_call: Any) -> str:
        """Safely extract the tool call function name."""
        if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
            return tool_call.function.name
        return tool_call.get('function', {}).get('name', 'unknown_function')
    
    def _create_assistant_message_with_tool_calls(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Create an assistant message including serialized tool calls."""
        assistant_msg = {
            "role": "assistant", 
            "content": response.get("content", "")
        }
        
        try:
            serializable_tool_calls = self._serialize_tool_calls(response["tool_calls"])
            assistant_msg["tool_calls"] = serializable_tool_calls
        except Exception as e:
            self.logger.error(f"Error serializing tool calls for memory: {str(e)}")
            
        return assistant_msg
    
    def _serialize_tool_calls(self, tool_calls: List[Any]) -> List[Dict[str, Any]]:
        """Convert tool calls to a serializable format for memory storage."""
        serializable_calls = []
        
        for tc in tool_calls:
            if hasattr(tc, 'id') and hasattr(tc, 'function'):
                serializable_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments
                    }
                })
            else:
                tc_dict = tc.copy() if isinstance(tc, dict) else tc
                if isinstance(tc_dict, dict) and "type" not in tc_dict:
                    tc_dict["type"] = "function"
                serializable_calls.append(tc_dict)
                
        return serializable_calls
    
    def _create_tool_messages(self, tool_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create tool messages from tool results."""
        tool_messages = []
        
        for result in tool_results:
            tool_messages.append({
                "role": "tool",
                "tool_call_id": result["tool_call_id"],
                "content": str(result.get("result", result.get("error", "")))
            })
            
        return tool_messages
    
    def _get_followup_response(self) -> Dict[str, Any]:
        """Get a follow-up response from the LLM incorporating tool results."""
        followup_messages = self._build_valid_message_sequence()
        
        try:
            followup_raw_response = self.llm_provider.chat_completion(
                messages=followup_messages,
                temperature=0.7
            )
            
            followup_response = self._standardize_followup_response(followup_raw_response)
            
            # Save the follow-up response to memory
            if followup_response.get("content"):
                self.memory.append({"role": "assistant", "content": followup_response["content"]})
                
            return followup_response
            
        except Exception as e:
            self.logger.error(f"Error in follow-up chat completion: {str(e)}")
            self._handle_followup_error()
            return {"content": "Error processing tool results."}
    
    def _build_valid_message_sequence(self) -> List[Dict[str, Any]]:
        """Build a valid message sequence for follow-up responses."""
        followup_messages = []
        has_tool_calls = False
        
        # Build a valid sequence with proper tool call references
        for msg in self.memory[-20:]:
            # Skip tool messages without preceding tool_calls
            if msg["role"] == "tool" and not has_tool_calls:
                self.logger.warning("Skipping tool message without preceding tool_calls")
                continue
            
            # Update tracking flags
            if msg["role"] == "user":
                has_tool_calls = False
            elif msg["role"] == "assistant" and "tool_calls" in msg:
                has_tool_calls = True
            
            followup_messages.append(msg)
        
        # Fallback if the sequence is invalid
        if not followup_messages or all(msg["role"] == "tool" for msg in followup_messages):
            for msg in self.memory:
                if msg["role"] == "user":
                    return [msg]
        
        return followup_messages
    
    def _standardize_followup_response(self, raw_response: Any) -> Dict[str, Any]:
        """Standardize the follow-up response format."""
        if hasattr(raw_response, 'choices') and raw_response.choices:
            return {"content": raw_response.choices[0].message.content or ""}
        return {"content": raw_response.get("content", "")}
    
    def _handle_followup_error(self) -> None:
        """Handle errors in follow-up responses by adding recovery messages to memory."""
        self.memory.append({"role": "user", "content": "Please continue."})
        self.memory.append({"role": "assistant", "content": "Error processing tool results. Let's continue."})
    
    def execute_tool(self, tool_call):
        """Execute a tool call and return the result."""
        try:
            # Extract function details from tool call
            function_info = self._extract_function_info(tool_call)
            function_name = function_info["name"]
            arguments = self._parse_arguments(function_info["arguments"])
            
            # Find and execute the function
            func = self._find_function(function_name)
            if not func:
                return {"error": f"Function {function_name} not found"}
                
            self.logger.debug(f"Executing function: {function_name} with arguments: {arguments}")
            return self._execute_function(func, arguments)
            
        except Exception as e:
            error_msg = f"Unexpected error executing tool call: {str(e)}"
            self.logger.error(error_msg)
            return {"error": error_msg}
    
    def _extract_function_info(self, tool_call: Any) -> Dict[str, Any]:
        """Extract function name and arguments from tool call."""
        if hasattr(tool_call, 'function'):
            return {
                "name": tool_call.function.name,
                "arguments": tool_call.function.arguments
            }
        return {
            "name": tool_call.get('function', {}).get('name', ''),
            "arguments": tool_call.get('function', {}).get('arguments', '{}')
        }
    
    def _parse_arguments(self, arguments_str: Any) -> Dict[str, Any]:
        """Parse function arguments from string or object."""
        self.logger.debug(f"Arguments (raw): {arguments_str}")
        
        try:
            if isinstance(arguments_str, str):
                arguments = json.loads(arguments_str)
            else:
                arguments = arguments_str
                
            self.logger.debug(f"Arguments (parsed): {arguments}")
            return arguments
        except json.JSONDecodeError as je:
            self.logger.error(f"Failed to parse arguments as JSON: {str(je)}")
            return {}
    
    def _find_function(self, function_name: str):
        """Find the function in available modules."""
        # Try general_tools first
        try:
            module = importlib.import_module("tools.general_tools")
            if hasattr(module, function_name):
                self.logger.debug(f"Found function in general_tools: {function_name}")
                return getattr(module, function_name)
        except ImportError:
            self.logger.error("Failed to import tools.general_tools")
        
        # Try security_tools module for security-related functions
        try:
            security_module = importlib.import_module("tools.security_tools")
            if hasattr(security_module, function_name):
                self.logger.debug(f"Found function in security_tools: {function_name}")
                return getattr(security_module, function_name)
        except ImportError:
            self.logger.error("Failed to import tools.security_tools")
        
        # Try specialized module based on function name prefix
        try:
            module_prefix = function_name.split("_")[0]
            specialized_module = importlib.import_module(f"tools.{module_prefix}_tools")
            self.logger.debug(f"Imported specialized module: tools.{module_prefix}_tools")
            if hasattr(specialized_module, function_name):
                return getattr(specialized_module, function_name)
        except (ImportError, AttributeError, IndexError):
            self.logger.error(f"Function {function_name} not found in specialized module")
        
        return None
    
    def _execute_function(self, func, arguments: Dict[str, Any]):
        """Execute the function with provided arguments."""
        try:
            result = func(**arguments)
            self.logger.debug("Tool execution successful")
            return result
        except TypeError as te:
            return self._handle_parameter_mismatch(func, arguments, te)
        except Exception as ex:
            error_msg = f"Error executing function: {str(ex)}"
            self.logger.error(error_msg)
            return {"error": error_msg}
    
    def _handle_parameter_mismatch(self, func, arguments: Dict[str, Any], error: TypeError):
        """Handle parameter mismatches with detailed error information."""
        import inspect
        
        try:
            sig = inspect.signature(func)
            required_params = [p.name for p in sig.parameters.values() 
                              if p.default == inspect.Parameter.empty 
                              and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)]
            
            missing_params = [p for p in required_params if p not in arguments]
            
            if missing_params:
                error_msg = f"Missing required parameters: {', '.join(missing_params)}"
            else:
                error_msg = f"Type error: {str(error)}"
                
            self.logger.error(error_msg)
            return {"error": error_msg}
        except Exception:
            return {"error": f"Parameter mismatch: {str(error)}"}
