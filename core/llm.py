from typing import Dict, List, Any, Optional, Union
import os
import json
import requests
import re

# Import LLM providers
import openai
from openai import OpenAI
import anthropic

from utils.logger import get_logger

class LLMProvider:
    """Provides a unified interface to different LLM providers."""
    
    def __init__(self, provider: str = "openai", model: str = "gpt-4o", openai_api_key: str = None, anthropic_api_key: str = None):
        self.provider = provider.lower()
        self.model = model
        self.logger = get_logger()
        
        # Use provided API keys if available, otherwise fall back to environment variables
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        
        # Initialize appropriate client
        if self.provider == "openai":
            self.client = OpenAI(api_key=self.openai_api_key)
            if not self._is_supported_openai_model(self.model):
                self.model = "gpt-4o"  # Default fallback for unknown OpenAI model names
        elif self.provider == "anthropic":
            try:
                # Try with the modern Anthropic API client structure
                self.client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            except (TypeError, AttributeError) as e:
                # If that fails, try the older client structure
                self.logger.warning(f"Failed to initialize modern Anthropic client: {str(e)}. Trying legacy client.")
                try:
                    self.client = anthropic.Client(api_key=self.anthropic_api_key)
                except Exception as e2:
                    self.logger.error(f"Failed to initialize legacy Anthropic client: {str(e2)}")
                    raise
                
            if not self.model.startswith("claude-"):
                self.model = "claude-3-5-sonnet"  # Default Claude model
        elif self.provider == "ollama":
            # Ollama doesn't need a client initialization since we'll use direct API calls
            # Just validate that we can connect to the Ollama server
            self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            try:
                # Test connection to Ollama server
                response = requests.get(f"{self.ollama_base_url}/api/tags")
                if response.status_code != 200:
                    raise ConnectionError(f"Failed to connect to Ollama server at {self.ollama_base_url}")
                
                # Validate that the model exists
                model_list = response.json().get("models", [])
                available_models = [model.get("name") for model in model_list]
                
                if not available_models:
                    self.logger.warning(f"No models found on Ollama server. You may need to pull a model first.")
                elif self.model not in available_models:
                    self.logger.warning(f"Model '{self.model}' not found on Ollama server. Available models: {', '.join(available_models)}")
                    if available_models:
                        self.logger.info(f"Defaulting to first available model: {available_models[0]}")
                        self.model = available_models[0]
                    else:
                        self.logger.warning("No models available. You need to pull a model first using: ollama pull <model>")
            except Exception as e:
                self.logger.error(f"Failed to initialize Ollama: {str(e)}")
                raise ValueError(f"Failed to connect to Ollama server at {self.ollama_base_url}. "
                                 f"Make sure Ollama is running and accessible. Error: {str(e)}")
        else:
            raise ValueError(f"Unsupported provider: {provider}. Use 'openai', 'anthropic', or 'ollama'.")
        
        self.logger.info(f"Initialized LLM provider: {self.provider} with model: {self.model}")

    @staticmethod
    def _is_supported_openai_model(model_name: str) -> bool:
        """Accept OpenAI GPT, Codex, ChatGPT, and O-series model naming patterns."""
        if not model_name:
            return False
        normalized = model_name.strip().lower()
        if normalized.startswith(("gpt-", "codex-", "chatgpt-")):
            return True
        return re.match(r"^o\d", normalized) is not None
    
    def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7, tools: Optional[List[Dict]] = None, json_mode: bool = False) -> Dict[str, Any]:
        """Generate a chat completion using the configured provider."""
        try:
            if self.provider == "openai":
                return self._openai_completion(messages, temperature, tools, json_mode)
            elif self.provider == "anthropic":
                return self._anthropic_completion(messages, temperature, tools, json_mode)
            elif self.provider == "ollama":
                return self._ollama_completion(messages, temperature, tools, json_mode)
        except Exception as e:
            self.logger.error(f"Error in LLM completion: {str(e)}")
            raise
    
    def _openai_completion(self, messages: List[Dict[str, str]], temperature: float, tools: Optional[List[Dict]], json_mode: bool) -> Union[Dict[str, Any], Any]:
        """Generate a completion using OpenAI."""
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        
        if tools:
            kwargs["tools"] = tools
        
        response = self.client.chat.completions.create(**kwargs)
        
        # Return the raw response object to better handle OpenAI's client structure
        return response
    
    def _ollama_completion(self, messages: List[Dict[str, str]], temperature: float, tools: Optional[List[Dict]], json_mode: bool) -> Union[Dict[str, Any], Any]:
        """Generate a completion using Ollama."""
        # Ollama API endpoint for chat completions
        endpoint = f"{self.ollama_base_url}/api/chat"
        
        # Check if we're dealing with a smaller model that needs special handling
        is_small_model = any(model_id in self.model.lower() 
                            for model_id in ["r1", "deepseek", "phi", "gemma", "mistral", "tiny"])
        
        # Prepare the request payload
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False
        }
        
        # Add format JSON if json_mode is True
        if json_mode:
            payload["format"] = "json"
        
        # Ollama doesn't support tools/functions natively, so we'll need to 
        # adapt the system message if tools are provided
        if tools:
            # For small models, use a simplified approach to tool description
            if is_small_model:
                # Simplify the tools representation for smaller models
                simple_tools = []
                for tool in tools:
                    if tool.get("type") == "function" and "function" in tool:
                        func_name = tool["function"].get("name", "unknown")
                        func_desc = tool["function"].get("description", "")
                        simple_tools.append(f"- {func_name}: {func_desc}")
                
                # Create simplified tool instructions with explicit examples
                tool_instructions = "\n".join([
                    "TOOLS YOU CAN USE:",
                    "\n".join(simple_tools),
                    "",
                    "IMPORTANT! To use a tool, respond with JSON like this example:",
                    "```json",
                    "{\"tool_calls\": [{\"id\": \"call_123\", \"type\": \"function\", \"function\": {\"name\": \"create_security_plan\", \"arguments\": \"{\\\"tasks\\\": [{\\\"type\\\": \\\"xss\\\", \\\"target\\\": \\\"form\\\", \\\"priority\\\": \\\"high\\\"}]}\"}}]}",
                    "```",
                    "Use this exact format with properly escaped quotes and valid JSON."
                ])
            else:
                # For larger models, provide more detailed tool information
                tool_instructions = f"You have access to the following tools:\n{json.dumps(tools, indent=2)}\n\n" + \
                                   "To use a tool, respond with a JSON object containing 'tool_calls' array with objects " + \
                                   "containing 'id', 'type': 'function', and 'function' with 'name' and 'arguments' (as a JSON string)."
            
            # Find or create a system message
            system_msg_exists = False
            for i, msg in enumerate(payload["messages"]):
                if msg["role"] == "system":
                    system_msg_exists = True
                    # Add tools info to existing system message
                    payload["messages"][i]["content"] += "\n\n" + tool_instructions
                    break
            
            # If no system message exists, create one with the tools information
            if not system_msg_exists:
                tools_msg = {
                    "role": "system",
                    "content": tool_instructions
                }
                # Insert at the beginning of messages
                payload["messages"].insert(0, tools_msg)
        
        # Make the API call
        try:
            response = requests.post(endpoint, json=payload)
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses
            
            result = response.json()
            
            # Create a wrapper compatible with our expected response format
            class OllamaWrapper:
                def __init__(self, result, model, is_small_model=False, logger=None):
                    self.logger = logger
                    message_content = result.get("message", {}).get("content", "")
                    tool_calls = []
                    
                    # Advanced parsing for tool calls from model outputs
                    if tools and message_content:
                        # First, try to extract JSON from the response directly
                        json_content = self._extract_json_from_text(message_content)
                        if json_content:
                            try:
                                parsed_json = json.loads(json_content)
                                
                                # Case 1: Response has the expected tool_calls format
                                if isinstance(parsed_json, dict) and "tool_calls" in parsed_json:
                                    if logger:
                                        logger.info("Found tool_calls in model response JSON")
                                    tool_calls = parsed_json["tool_calls"]
                                    # Clean up the message content
                                    message_content = self._remove_json_from_text(message_content, json_content)
                                
                                # Case 2: Response is a direct function call with name and arguments
                                elif isinstance(parsed_json, dict) and "name" in parsed_json and "arguments" in parsed_json:
                                    if logger:
                                        logger.info(f"Found direct function call format: {parsed_json['name']}")
                                    # Generate a unique ID
                                    import hashlib
                                    call_id = f"call_{hashlib.md5(str(parsed_json).encode()).hexdigest()[:8]}"
                                    
                                    # Handle case where arguments might be a string or object
                                    args = parsed_json["arguments"]
                                    if isinstance(args, dict):
                                        args_str = json.dumps(args)
                                    else:
                                        args_str = args
                                    
                                    tool_calls = [{
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": parsed_json["name"],
                                            "arguments": args_str
                                        }
                                    }]
                                    message_content = self._remove_json_from_text(message_content, json_content)
                                
                                # Case 3: Look for create_security_plan with direct tasks list (common in small models)
                                elif isinstance(parsed_json, dict) and "tasks" in parsed_json:
                                    if logger:
                                        logger.info("Found tasks list in JSON")
                                    # Assume this is for create_security_plan
                                    import hashlib
                                    call_id = f"call_{hashlib.md5(str(parsed_json).encode()).hexdigest()[:8]}"
                                    
                                    tool_calls = [{
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": "create_security_plan",
                                            "arguments": json.dumps({"tasks": parsed_json["tasks"]})
                                        }
                                    }]
                                    message_content = self._remove_json_from_text(message_content, json_content)
                            except (json.JSONDecodeError, KeyError) as e:
                                if logger:
                                    logger.warning(f"Error parsing JSON from model response: {str(e)}")
                        
                        # If still no tool calls, try to parse from text patterns
                        if not tool_calls:
                            tool_calls = self._parse_function_calls_from_text(message_content, tools, is_small_model)
                            if tool_calls and logger:
                                logger.info(f"Extracted function call from text: {tool_calls[0]['function']['name']}")
                    
                    self.choices = [
                        type('Choice', (), {
                            'message': type('Message', (), {
                                'content': message_content,
                                'tool_calls': tool_calls
                            }),
                            'finish_reason': result.get("done", True) and "stop" or "length"
                        })
                    ]
                    self.model = model
                
                def _extract_json_from_text(self, text):
                    """Extract JSON object from text content, even if surrounded by markdown code blocks."""
                    # Try to extract JSON from markdown code blocks first (preferred)
                    import re
                    
                    # Look for JSON inside code blocks
                    code_block_pattern = r'```(?:json)?\s*([\s\S]*?)```'
                    code_matches = re.findall(code_block_pattern, text)
                    
                    for match in code_matches:
                        # Check if the match starts with { and ends with }
                        stripped = match.strip()
                        if stripped.startswith('{') and stripped.endswith('}'):
                            return stripped
                    
                    # Look for standalone JSON objects
                    json_pattern = r'({[\s\S]*?})'
                    json_matches = re.findall(json_pattern, text)
                    
                    for match in json_matches:
                        # Validate this looks like a JSON object
                        stripped = match.strip()
                        # Check for keywords to ensure this is likely a tool call
                        if any(keyword in stripped.lower() for keyword in 
                              ["tool_calls", "function", "name", "arguments", "tasks", "type", "create_security_plan"]):
                            return stripped
                    
                    # If the entire text is a JSON object
                    text = text.strip()
                    if text.startswith('{') and text.endswith('}'):
                        return text
                    
                    return None
                
                def _remove_json_from_text(self, text, json_content):
                    """Remove the JSON content from the text to avoid duplication."""
                    if not json_content:
                        return text
                    
                    # Remove the JSON content directly
                    cleaned = text.replace(json_content, "")
                    
                    # Remove markdown code blocks that might contain the JSON
                    import re
                    cleaned = re.sub(r'```(?:json)?\s*' + re.escape(json_content) + r'\s*```', '', cleaned)
                    
                    # Clean up any remaining code block markers
                    cleaned = re.sub(r'```(?:json)?\s*```', '', cleaned)
                    
                    return cleaned.strip()
                
                def _parse_function_calls_from_text(self, text, tools, is_small_model):
                    """Parse function calls from text patterns commonly found in model outputs."""
                    import re
                    tool_calls = []
                    
                    # Look for the create_security_plan function call syntax in text
                    if is_small_model:
                        # Simple pattern for create_security_plan with tasks parameter
                        pattern = r'create_security_plan\s*\(\s*tasks\s*=\s*(\[[\s\S]*?\])\s*\)'
                        match = re.search(pattern, text, re.IGNORECASE)
                        
                        if match:
                            tasks_str = match.group(1)
                            # Try to fix common JSON issues
                            tasks_str = tasks_str.replace("'", "\"")
                            
                            try:
                                tasks = json.loads(tasks_str)
                                import hashlib
                                call_id = f"call_{hashlib.md5(tasks_str.encode()).hexdigest()[:8]}"
                                
                                tool_calls = [{
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": "create_security_plan",
                                        "arguments": json.dumps({"tasks": tasks})
                                    }
                                }]
                            except json.JSONDecodeError:
                                pass
                    
                    return tool_calls
            
            return OllamaWrapper(result, self.model, is_small_model, self.logger)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ollama API request failed: {str(e)}")
            raise
        except json.JSONDecodeError:
            self.logger.error(f"Failed to parse Ollama API response")
            raise ValueError("Invalid response from Ollama API")
    
    def _anthropic_completion(self, messages: List[Dict[str, str]], temperature: float, tools: Optional[List[Dict]], json_mode: bool) -> Union[Dict[str, Any], Any]:
        """Generate a completion using Anthropic."""
        # Convert chat format to Anthropic format
        anthropic_messages = []
        
        for msg in messages:
            role = "assistant" if msg["role"] == "assistant" else "user" if msg["role"] == "user" else "system"
            content = msg["content"]
            anthropic_messages.append({"role": role, "content": content})
        
        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "temperature": temperature,
            "max_tokens": 4000
        }
        
        if tools:
            kwargs["tools"] = tools
        
        # Check how the Anthropic client is structured and use the appropriate method
        if hasattr(self.client, "messages") and hasattr(self.client.messages, "create"):
            # New Anthropic client structure
            response = self.client.messages.create(**kwargs)
            
            # For new API format, convert to a format compatible with our code's expectations
            if hasattr(response, "tool_uses") and response.tool_uses:
                tool_calls = []
                for tool_use in response.tool_uses:
                    tool_calls.append({
                        "id": tool_use.id,
                        "type": "function",  # Always include type
                        "function": {
                            "name": tool_use.name,
                            "arguments": json.dumps(tool_use.input)
                        }
                    })
                
                # Create a wrapper object similar to OpenAI's format for compatibility
                class CompatibilityWrapper:
                    def __init__(self, response, tool_calls):
                        self.choices = [
                            type('Choice', (), {
                                'message': type('Message', (), {
                                    'content': response.content[0].text if response.content else "",
                                    'tool_calls': tool_calls
                                }),
                                'finish_reason': response.stop_reason
                            })
                        ]
                        self.model = response.model
                
                return CompatibilityWrapper(response, tool_calls)
            else:
                # No tools, simpler wrapper
                class CompatibilityWrapper:
                    def __init__(self, response):
                        self.choices = [
                            type('Choice', (), {
                                'message': type('Message', (), {
                                    'content': response.content[0].text if response.content else "",
                                    'tool_calls': []
                                }),
                                'finish_reason': response.stop_reason
                            })
                        ]
                        self.model = response.model
                
                return CompatibilityWrapper(response)
        else:
            # Older Anthropic client structure (Claude v1 API)
            # Convert messages to single prompt for older API
            prompt = ""
            for msg in anthropic_messages:
                if msg["role"] == "system":
                    prompt += f"{msg['content']}\n\n"
                elif msg["role"] == "user":
                    prompt += f"\n\nHuman: {msg['content']}"
                elif msg["role"] == "assistant":
                    prompt += f"\n\nAssistant: {msg['content']}"
            
            # Add the final Assistant prompt
            prompt += "\n\nAssistant:"
            
            # Set up the parameters for the older API
            old_kwargs = {
                "prompt": prompt,
                "model": self.model,
                "max_tokens_to_sample": 4000,
                "temperature": temperature,
                "stop_sequences": ["\n\nHuman:"]
            }
            
            response = self.client.completion(**old_kwargs)
            
            # Create a simple wrapper object for old API
            class OldApiWrapper:
                def __init__(self, response, model):
                    self.choices = [
                        type('Choice', (), {
                            'message': type('Message', (), {
                                'content': response.completion,
                                'tool_calls': []
                            }),
                            'finish_reason': 'stop'
                        })
                    ]
                    self.model = model
            
            return OldApiWrapper(response, self.model)
    
    def create_embedding(self, text: str) -> List[float]:
        """Generate embeddings for the given text."""
        if self.provider == "openai":
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        elif self.provider == "ollama":
            # Check if Ollama server supports embeddings
            try:
                response = requests.post(
                    f"{self.ollama_base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text}
                )
                if response.status_code == 200:
                    return response.json().get("embedding", [])
                else:
                    self.logger.warning(f"Ollama embeddings failed, falling back to OpenAI: {response.text}")
            except Exception as e:
                self.logger.warning(f"Ollama embeddings error, falling back to OpenAI: {str(e)}")
            
            # If Ollama embedding fails, fall back to OpenAI
            self.logger.info("Falling back to OpenAI for embeddings")
            fallback_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        else:
            # Anthropic doesn't currently support embeddings, fall back to OpenAI
            fallback_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
