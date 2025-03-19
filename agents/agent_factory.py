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
        """Process input data and generate a thoughtful response."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Add context from memory
        # Use fewer memory items for Ollama to reduce context length
        memory_limit = 3 if hasattr(self.llm_provider, 'provider') and self.llm_provider.provider == "ollama" else 5
        for mem in self.memory[-memory_limit:]:
            messages.append(mem)
        
        # Add the current input
        if isinstance(input_data, dict) and "content" in input_data:
            messages.append({"role": "user", "content": input_data["content"]})
        elif isinstance(input_data, str):
            messages.append({"role": "user", "content": input_data})
        else:
            input_text = f"Process the following information: {input_data}"
            messages.append({"role": "user", "content": input_text})
        
        # Adjust temperature based on provider
        # Use lower temperature for Ollama to improve reliability
        temperature = 0.5 if hasattr(self.llm_provider, 'provider') and self.llm_provider.provider == "ollama" else 0.7
        
        # Check if we're using a small Ollama model that might need even more temperature adjustment
        if (hasattr(self.llm_provider, 'provider') and self.llm_provider.provider == "ollama" and
            hasattr(self.llm_provider, 'model') and 
            any(small_model in self.llm_provider.model.lower() for small_model in ["r1", "deepseek", "phi", "gemma", "mistral"])):
            temperature = 0.2  # Even lower temperature for smaller models
            self.logger.debug(f"Using low temperature (0.2) for small Ollama model: {self.llm_provider.model}")
        
        # Generate response
        raw_response = self.llm_provider.chat_completion(
            messages=messages,
            temperature=temperature,
            tools=self.tools if self.tools else None
        )
        
        # Convert the response to a standardized format
        response = {}
        
        # Handle content
        if hasattr(raw_response, 'choices') and raw_response.choices:
            first_choice = raw_response.choices[0]
            response["content"] = first_choice.message.content if first_choice.message.content else ""
            # Handle tool calls
            if hasattr(first_choice.message, 'tool_calls') and first_choice.message.tool_calls:
                response["tool_calls"] = first_choice.message.tool_calls
        else:
            # Fallback for dictionary-style responses (older structure)
            response["content"] = raw_response.get("content", "")
            response["tool_calls"] = raw_response.get("tool_calls", [])
        
        # Save the user message to memory if not already there
        last_user_msg = messages[-1]["content"]
        if not self.memory or self.memory[-1]["role"] != "user" or self.memory[-1]["content"] != last_user_msg:
            self.memory.append({"role": "user", "content": last_user_msg})
        
        # Handle the assistant's response and any tool calls
        if response.get("tool_calls"):
            # Process and execute tool calls
            tool_results = []
            for tool_call in response["tool_calls"]:
                try:
                    tool_result = self.execute_tool(tool_call)
                    # Get the tool_call_id and name safely
                    if hasattr(tool_call, 'id') and hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
                        tool_call_id = tool_call.id
                        tool_name = tool_call.function.name
                    else:
                        tool_call_id = tool_call.get('id', 'unknown_id')
                        tool_name = tool_call.get('function', {}).get('name', 'unknown_function')
                    
                    tool_results.append({
                        "tool_call_id": tool_call_id,
                        "name": tool_name,
                        "result": tool_result
                    })
                except Exception as e:
                    self.logger.error(f"Error executing tool: {str(e)}")
                    # Get ID and name safely
                    if hasattr(tool_call, 'id') and hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
                        tool_call_id = tool_call.id
                        tool_name = tool_call.function.name
                    else:
                        tool_call_id = tool_call.get('id', 'unknown_id')
                        tool_name = tool_call.get('function', {}).get('name', 'unknown_function')
                    
                    tool_results.append({
                        "tool_call_id": tool_call_id,
                        "name": tool_name,
                        "error": str(e)
                    })
            
            # Save assistant message with tool calls
            assistant_msg = {
                "role": "assistant", 
                "content": response.get("content", "")
            }
            # Add tool_calls if they can be properly serialized
            try:
                # Try to convert tool_calls to a format that can be stored in memory
                serializable_tool_calls = []
                for tc in response["tool_calls"]:
                    if hasattr(tc, 'id') and hasattr(tc, 'function'):
                        serializable_tool_calls.append({
                            "id": tc.id,
                            "type": "function",  # Always add the type field
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        })
                    else:
                        # Make sure the dict format also has type field
                        tc_dict = tc.copy() if isinstance(tc, dict) else tc
                        if isinstance(tc_dict, dict) and "type" not in tc_dict:
                            tc_dict["type"] = "function"
                        serializable_tool_calls.append(tc_dict)
                        
                assistant_msg["tool_calls"] = serializable_tool_calls
            except Exception as e:
                self.logger.error(f"Error serializing tool calls for memory: {str(e)}")
                # Skip adding tool_calls to memory
            
            self.memory.append(assistant_msg)
            
            # Prepare tool messages and verify message sequence integrity
            tool_messages = []
            for tool_result in tool_results:
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": tool_result["tool_call_id"],
                    "content": str(tool_result.get("result", tool_result.get("error", "")))
                }
                # The 'name' field is not needed and can cause issues with OpenAI's API
                tool_messages.append(tool_msg)
                self.memory.append(tool_msg)
            
            # Ensure proper sequence for OpenAI - verify we have assistant message with tool_calls before tool messages
            followup_messages = []
            has_tool_calls = False
            
            # Build a valid message sequence with proper tool call references
            for msg in self.memory[-20:]:  # Use more context but filter properly
                # Skip any tool messages that don't have a preceding message with tool_calls
                if msg["role"] == "tool" and not has_tool_calls:
                    self.logger.warning("Skipping tool message without preceding tool_calls")
                    continue
                
                # Reset the flag when we see a user message
                if msg["role"] == "user":
                    has_tool_calls = False
                
                # Set the flag when we see a message with tool_calls
                if msg["role"] == "assistant" and "tool_calls" in msg:
                    has_tool_calls = True
                
                followup_messages.append(msg)
            
            # If followup_messages is empty or invalid, just use the most recent user message
            if not followup_messages or all(msg["role"] == "tool" for msg in followup_messages):
                for msg in self.memory:
                    if msg["role"] == "user":
                        followup_messages = [msg]
                        break
            
            # Get a follow-up response from the LLM incorporating the tool results
            try:
                followup_raw_response = self.llm_provider.chat_completion(
                    messages=followup_messages,
                    temperature=0.7
                )
            except Exception as e:
                self.logger.error(f"Error in follow-up chat completion: {str(e)}")
                # Fall back to a simpler response without tool results
                followup_raw_response = {"content": "Error processing tool results."}
                # Create a new user message to prevent sequence issues in future requests
                self.memory.append({"role": "user", "content": "Please continue."})
                self.memory.append({"role": "assistant", "content": "Error processing tool results. Let's continue."})
            
            # Convert to standardized format
            followup_response = {}
            if hasattr(followup_raw_response, 'choices') and followup_raw_response.choices:
                followup_response["content"] = followup_raw_response.choices[0].message.content if followup_raw_response.choices[0].message.content else ""
            else:
                followup_response["content"] = followup_raw_response.get("content", "")
            
            # Save the follow-up response
            if followup_response.get("content"):
                self.memory.append({"role": "assistant", "content": followup_response["content"]})
            
            # Include the tool results in the response
            response["tool_results"] = tool_results
            response["followup_response"] = followup_response
            
        else:
            # Regular response with no tool calls
            self.memory.append({"role": "assistant", "content": response["content"]})
        
        return response
    
    def execute_tool(self, tool_call):
        """Execute a tool call and return the result."""
        try:
            # Check if we're dealing with the new OpenAI client structure or a dictionary
            if hasattr(tool_call, 'function'):
                function_name = tool_call.function.name
                arguments_str = tool_call.function.arguments
                tool_call_id = getattr(tool_call, 'id', 'unknown_id')
                # Make sure we have a type field for consistent message formatting
                tool_type = "function"
            else:
                # Handle dict format for older versions or different structures
                function_name = tool_call.get('function', {}).get('name', '')
                arguments_str = tool_call.get('function', {}).get('arguments', '{}')
                tool_call_id = tool_call.get('id', 'unknown_id')
                tool_type = tool_call.get('type', 'function')
            
            # Debug info
            self.logger.debug(f"Executing tool: {function_name}")
            self.logger.debug(f"Arguments (raw): {arguments_str}")
            
            # Parse arguments as JSON
            try:
                if isinstance(arguments_str, str):
                    arguments = json.loads(arguments_str)
                else:
                    arguments = arguments_str
                self.logger.debug(f"Arguments (parsed): {arguments}")
            except json.JSONDecodeError as je:
                self.logger.error(f"Failed to parse arguments as JSON: {str(je)}")
                return {"error": f"Invalid arguments format: {str(je)}"}
            
            # First, try to find the function in general_tools (since we've moved most there)
            module_name = "tools.general_tools"
            try:
                module = importlib.import_module(module_name)
                if hasattr(module, function_name):
                    self.logger.debug(f"Found function in general_tools: {function_name}")
                    # Get the function from the module
                    func = getattr(module, function_name)
                else:
                    # If not in general_tools, try specialized modules
                    specialized_module_name = "tools." + function_name.split("_")[0] + "_tools"
                    try:
                        module = importlib.import_module(specialized_module_name)
                        self.logger.debug(f"Imported specialized module: {specialized_module_name}")
                        # Get the function from the module
                        func = getattr(module, function_name)
                    except (ImportError, AttributeError) as e:
                        self.logger.error(f"Function {function_name} not found in any module: {str(e)}")
                        return {"error": f"Function {function_name} not found: {str(e)}"}
            except ImportError as e:
                self.logger.error(f"Failed to import tools.general_tools: {str(e)}")
                return {"error": f"Module import error: {str(e)}"}
            
            self.logger.debug(f"Executing function: {function_name} with arguments: {arguments}")
            
            # Execute the function with the parsed arguments
            try:
                result = func(**arguments)
                self.logger.debug(f"Tool execution successful for {function_name}")
                return result
            except TypeError as te:
                # Try to provide more detailed error information for parameter mismatches
                import inspect
                sig = inspect.signature(func)
                required_params = [p.name for p in sig.parameters.values() 
                                  if p.default == inspect.Parameter.empty 
                                  and p.kind != inspect.Parameter.VAR_POSITIONAL 
                                  and p.kind != inspect.Parameter.VAR_KEYWORD]
                missing_params = [p for p in required_params if p not in arguments]
                
                if missing_params:
                    error_msg = f"Missing required parameters for {function_name}: {', '.join(missing_params)}"
                else:
                    error_msg = f"Type error in {function_name}: {str(te)}"
                    
                self.logger.error(error_msg)
                return {"error": error_msg}
            except Exception as ex:
                error_msg = f"Error executing {function_name}: {str(ex)}"
                self.logger.error(error_msg)
                return {"error": error_msg}
            
        except Exception as e:
            error_msg = f"Unexpected error executing tool call: {str(e)}"
            self.logger.error(error_msg)
            return {"error": error_msg}
