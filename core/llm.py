from typing import Dict, List, Any, Optional, Union
import os
import json

# Import LLM providers
import openai
from openai import OpenAI
import anthropic

from utils.logger import get_logger

class LLMProvider:
    """Provides a unified interface to different LLM providers."""
    
    def __init__(self, provider: str = "openai", model: str = "gpt-4o"):
        self.provider = provider.lower()
        self.model = model
        self.logger = get_logger()
        
        # Initialize appropriate client
        if self.provider == "openai":
            self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            if not self.model.startswith("gpt-"):
                self.model = "gpt-4o"  # Default to GPT-4o if not specified correctly
        elif self.provider == "anthropic":
            try:
                # Try with the modern Anthropic API client structure
                self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            except (TypeError, AttributeError) as e:
                # If that fails, try the older client structure
                self.logger.warning(f"Failed to initialize modern Anthropic client: {str(e)}. Trying legacy client.")
                try:
                    self.client = anthropic.Client(api_key=os.getenv("ANTHROPIC_API_KEY"))
                except Exception as e2:
                    self.logger.error(f"Failed to initialize legacy Anthropic client: {str(e2)}")
                    raise
                
            if not self.model.startswith("claude-"):
                self.model = "claude-3-5-sonnet"  # Default Claude model
        else:
            raise ValueError(f"Unsupported provider: {provider}. Use 'openai' or 'anthropic'.")
        
        self.logger.info(f"Initialized LLM provider: {self.provider} with model: {self.model}")
    
    def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7, tools: Optional[List[Dict]] = None, json_mode: bool = False) -> Dict[str, Any]:
        """Generate a chat completion using the configured provider."""
        try:
            if self.provider == "openai":
                return self._openai_completion(messages, temperature, tools, json_mode)
            elif self.provider == "anthropic":
                return self._anthropic_completion(messages, temperature, tools, json_mode)
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
        else:
            # Anthropic doesn't currently support embeddings, fall back to OpenAI
            fallback_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
