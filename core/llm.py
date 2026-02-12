from typing import Dict, List, Any, Optional, Union
import os
import json
import requests
import re
import uuid

# Import LLM providers
from openai import OpenAI

try:
    import anthropic
except Exception:
    anthropic = None

try:
    import google.generativeai as genai
    from google.generativeai import types as genai_types  # Use alias
    from google.api_core import exceptions as google_api_exceptions
except Exception:
    genai = None
    genai_types = None
    google_api_exceptions = None

from utils.logger import get_logger
from utils.config import load_config  # Added for config loading


class LLMProvider:
    """Provides a unified interface to different LLM providers."""

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        openai_api_key: str = None,
        anthropic_api_key: str = None,
        google_api_key: str = None,
    ):
        self.provider = provider.lower()
        self.model = model
        self.logger = get_logger()
        self.config = load_config()  # Load configuration on initialization

        # Use provided API keys if available, otherwise fall back to environment variables
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.google_api_key = google_api_key or os.getenv(
            "GOOGLE_API_KEY"
        )  # Added Gemini key handling

        # Initialize appropriate client
        if self.provider == "openai":
            self.client = OpenAI(api_key=self.openai_api_key)
            normalized_openai_model = self._normalize_model_name(self.model)
            if self._is_supported_openai_model(normalized_openai_model):
                self.model = normalized_openai_model
            else:
                self.model = "gpt-4o"  # Default fallback for unknown OpenAI model names
        elif self.provider == "anthropic":
            if anthropic is None:
                raise ValueError(
                    "Anthropic SDK is not installed. Install dependency: anthropic."
                )
            try:
                # Try with the modern Anthropic API client structure
                self.client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            except (TypeError, AttributeError) as e:
                # If that fails, try the older client structure
                self.logger.warning(
                    f"Failed to initialize modern Anthropic client: {str(e)}. Trying legacy client."
                )
                try:
                    self.client = anthropic.Client(api_key=self.anthropic_api_key)
                except Exception as e2:
                    self.logger.error(
                        f"Failed to initialize legacy Anthropic client: {str(e2)}"
                    )
                    raise

            if not self.model.startswith("claude-"):
                self.model = "claude-3-5-sonnet"  # Default Claude model
        elif self.provider == "ollama":
            # Ollama doesn't need a client initialization since we'll use direct API calls
            # Just validate that we can connect to the Ollama server
            self.ollama_base_url = os.getenv(
                "OLLAMA_BASE_URL", "http://localhost:11434"
            )
            try:
                # Test connection to Ollama server
                response = requests.get(f"{self.ollama_base_url}/api/tags")
                if response.status_code != 200:
                    raise ConnectionError(
                        f"Failed to connect to Ollama server at {self.ollama_base_url}"
                    )

                # Validate that the model exists
                model_list = response.json().get("models", [])
                available_models = [model.get("name") for model in model_list]

                if not available_models:
                    self.logger.warning(
                        "No models found on Ollama server. You may need to pull a model first."
                    )
                elif self.model not in available_models:
                    self.logger.warning(
                        f"Model '{self.model}' not found on Ollama server. Available models: {', '.join(available_models)}"
                    )
                    if available_models:
                        self.logger.info(
                            f"Defaulting to first available model: {available_models[0]}"
                        )
                        self.model = available_models[0]
                    else:
                        self.logger.warning(
                            "No models available. You need to pull a model first using: ollama pull <model>"
                        )
            except Exception as e:
                self.logger.error(f"Failed to initialize Ollama: {str(e)}")
                raise ValueError(
                    f"Failed to connect to Ollama server at {self.ollama_base_url}. "
                    f"Make sure Ollama is running and accessible. Error: {str(e)}"
                )
        elif self.provider == "gemini":  # Added Gemini initialization
            if genai is None:
                raise ValueError(
                    "Google Gemini SDK is not installed. Install dependency: google-generativeai."
                )
            if not self.google_api_key:
                self.logger.error("Google API Key not found for Gemini provider.")
                raise ValueError(
                    "Google API Key not found. Set GOOGLE_API_KEY environment variable or provide via API/constructor."
                )
            try:
                genai.configure(api_key=self.google_api_key)

                # Determine the Gemini model to use based on priority
                resolved_model = self.model  # Start with the model passed to __init__

                # Check if the provided model is likely not a Gemini model (e.g., default "gpt-4o")
                # or if it's None/empty (although __init__ has a default, belt-and-suspenders)
                if not isinstance(resolved_model, str) or not resolved_model.startswith(
                    "gemini-"
                ):
                    self.logger.debug(
                        f"Initial model '{resolved_model}' is not Gemini-specific or invalid. Checking config..."
                    )
                    # Try to get the default from config
                    # Use self.config loaded earlier
                    gemini_config = self.config.get("llm", {}).get("gemini", {})
                    default_model = gemini_config.get("default_model")

                    if (
                        default_model
                        and isinstance(default_model, str)
                        and default_model.strip()
                    ):
                        resolved_model = default_model.strip()
                        self.logger.info(
                            f"Using default Gemini model from config: {resolved_model}"
                        )
                    else:
                        # Fallback to hardcoded default if config is missing or empty
                        resolved_model = (
                            "gemini-2.0-flash-thinking-exp-01-21"  # Hardcoded fallback
                        )
                        self.logger.warning(
                            f"Gemini 'default_model' not found or invalid in config. Using hardcoded fallback: {resolved_model}"
                        )
                else:
                    self.logger.debug(
                        f"Using provided Gemini-specific model: {resolved_model}"
                    )

                self.model = resolved_model  # Update self.model with the resolved name
                self.gemini_model = genai.GenerativeModel(self.model)
                self.logger.info(
                    f"Successfully initialized Gemini client with model: {self.model}"
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to initialize Google Gemini client: {str(e)}",
                    exc_info=True,
                )  # Add exc_info for better debugging
                raise ValueError(f"Failed to initialize Google Gemini client: {str(e)}")
        else:
            raise ValueError(
                f"Unsupported provider: {self.provider}. Use 'openai', 'anthropic', 'ollama', or 'gemini'."
            )

        self.logger.info(
            f"Initialized LLM provider: {self.provider} with model: {self.model}"
        )

    @staticmethod
    def _normalize_model_name(model_name: Optional[str]) -> str:
        if not isinstance(model_name, str):
            return ""
        return model_name.strip().lower()

    @classmethod
    def _is_supported_openai_model(cls, model_name: str) -> bool:
        """Accept OpenAI GPT, ChatGPT, and O-series model naming patterns."""
        normalized = cls._normalize_model_name(model_name)
        if not normalized:
            return False
        if normalized.startswith(("gpt-", "chatgpt-")):
            return True
        return re.match(r"^o\d", normalized) is not None

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None,
        json_mode: bool = False,
    ) -> Dict[str, Any]:
        """Generate a chat completion using the configured provider."""
        try:
            if self.provider == "openai":
                return self._openai_completion(messages, temperature, tools, json_mode)
            elif self.provider == "anthropic":
                return self._anthropic_completion(
                    messages, temperature, tools, json_mode
                )
            elif self.provider == "ollama":
                return self._ollama_completion(messages, temperature, tools, json_mode)
            elif self.provider == "gemini":  # Added Gemini routing
                # Note: Pass json_mode even if Gemini doesn't directly support it yet,
                #       for consistency. It might be used for internal logic later.
                return self._gemini_completion(messages, temperature, tools, json_mode)
        except Exception as e:
            self.logger.error(f"Error in LLM completion: {str(e)}")
            raise

    def _openai_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        tools: Optional[List[Dict]],
        json_mode: bool,
    ) -> Union[Dict[str, Any], Any]:
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

    def _ollama_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        tools: Optional[List[Dict]],
        json_mode: bool,
    ) -> Union[Dict[str, Any], Any]:
        """Generate a completion using Ollama."""
        # Ollama API endpoint for chat completions
        endpoint = f"{self.ollama_base_url}/api/chat"

        # Check if we're dealing with a smaller model that needs special handling
        is_small_model = any(
            model_id in self.model.lower()
            for model_id in ["r1", "deepseek", "phi", "gemma", "mistral", "tiny"]
        )

        # Prepare the request payload
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
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
                tool_instructions = "\n".join(
                    [
                        "TOOLS YOU CAN USE:",
                        "\n".join(simple_tools),
                        "",
                        "IMPORTANT! To use a tool, respond with JSON like this example:",
                        "```json",
                        '{"tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "create_security_plan", "arguments": "{\\"tasks\\": [{\\"type\\": \\"xss\\", \\"target\\": \\"form\\", \\"priority\\": \\"high\\"}]}"}}]}',
                        "```",
                        "Use this exact format with properly escaped quotes and valid JSON.",
                    ]
                )
            else:
                # For larger models, provide more detailed tool information
                tool_instructions = (
                    f"You have access to the following tools:\n{json.dumps(tools, indent=2)}\n\n"
                    + "To use a tool, respond with a JSON object containing 'tool_calls' array with objects "
                    + "containing 'id', 'type': 'function', and 'function' with 'name' and 'arguments' (as a JSON string)."
                )

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
                tools_msg = {"role": "system", "content": tool_instructions}
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
                                if (
                                    isinstance(parsed_json, dict)
                                    and "tool_calls" in parsed_json
                                ):
                                    if logger:
                                        logger.info(
                                            "Found tool_calls in model response JSON"
                                        )
                                    tool_calls = parsed_json["tool_calls"]
                                    # Clean up the message content
                                    message_content = self._remove_json_from_text(
                                        message_content, json_content
                                    )

                                # Case 2: Response is a direct function call with name and arguments
                                elif (
                                    isinstance(parsed_json, dict)
                                    and "name" in parsed_json
                                    and "arguments" in parsed_json
                                ):
                                    if logger:
                                        logger.info(
                                            f"Found direct function call format: {parsed_json['name']}"
                                        )
                                    # Generate a unique ID
                                    import hashlib

                                    call_id = f"call_{hashlib.md5(str(parsed_json).encode()).hexdigest()[:8]}"

                                    # Handle case where arguments might be a string or object
                                    args = parsed_json["arguments"]
                                    if isinstance(args, dict):
                                        args_str = json.dumps(args)
                                    else:
                                        args_str = args

                                    tool_calls = [
                                        {
                                            "id": call_id,
                                            "type": "function",
                                            "function": {
                                                "name": parsed_json["name"],
                                                "arguments": args_str,
                                            },
                                        }
                                    ]
                                    message_content = self._remove_json_from_text(
                                        message_content, json_content
                                    )

                                # Case 3: Look for create_security_plan with direct tasks list (common in small models)
                                elif (
                                    isinstance(parsed_json, dict)
                                    and "tasks" in parsed_json
                                ):
                                    if logger:
                                        logger.info("Found tasks list in JSON")
                                    # Assume this is for create_security_plan
                                    import hashlib

                                    call_id = f"call_{hashlib.md5(str(parsed_json).encode()).hexdigest()[:8]}"

                                    tool_calls = [
                                        {
                                            "id": call_id,
                                            "type": "function",
                                            "function": {
                                                "name": "create_security_plan",
                                                "arguments": json.dumps(
                                                    {"tasks": parsed_json["tasks"]}
                                                ),
                                            },
                                        }
                                    ]
                                    message_content = self._remove_json_from_text(
                                        message_content, json_content
                                    )
                            except (json.JSONDecodeError, KeyError) as e:
                                if logger:
                                    logger.warning(
                                        f"Error parsing JSON from model response: {str(e)}"
                                    )

                        # If still no tool calls, try to parse from text patterns
                        if not tool_calls:
                            tool_calls = self._parse_function_calls_from_text(
                                message_content, tools, is_small_model
                            )
                            if tool_calls and logger:
                                logger.info(
                                    f"Extracted function call from text: {tool_calls[0]['function']['name']}"
                                )

                    self.choices = [
                        type(
                            "Choice",
                            (),
                            {
                                "message": type(
                                    "Message",
                                    (),
                                    {
                                        "content": message_content,
                                        "tool_calls": tool_calls,
                                    },
                                ),
                                "finish_reason": result.get("done", True)
                                and "stop"
                                or "length",
                            },
                        )
                    ]
                    self.model = model

                def _extract_json_from_text(self, text):
                    """Extract JSON object from text content, even if surrounded by markdown code blocks."""
                    # Try to extract JSON from markdown code blocks first (preferred)
                    import re

                    # Look for JSON inside code blocks
                    code_block_pattern = r"```(?:json)?\s*([\s\S]*?)```"
                    code_matches = re.findall(code_block_pattern, text)

                    for match in code_matches:
                        # Check if the match starts with { and ends with }
                        stripped = match.strip()
                        if stripped.startswith("{") and stripped.endswith("}"):
                            return stripped

                    # Look for standalone JSON objects
                    json_pattern = r"({[\s\S]*?})"
                    json_matches = re.findall(json_pattern, text)

                    for match in json_matches:
                        # Validate this looks like a JSON object
                        stripped = match.strip()
                        # Check for keywords to ensure this is likely a tool call
                        if any(
                            keyword in stripped.lower()
                            for keyword in [
                                "tool_calls",
                                "function",
                                "name",
                                "arguments",
                                "tasks",
                                "type",
                                "create_security_plan",
                            ]
                        ):
                            return stripped

                    # If the entire text is a JSON object
                    text = text.strip()
                    if text.startswith("{") and text.endswith("}"):
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

                    cleaned = re.sub(
                        r"```(?:json)?\s*" + re.escape(json_content) + r"\s*```",
                        "",
                        cleaned,
                    )

                    # Clean up any remaining code block markers
                    cleaned = re.sub(r"```(?:json)?\s*```", "", cleaned)

                    return cleaned.strip()

                def _parse_function_calls_from_text(self, text, tools, is_small_model):
                    """Parse function calls from text patterns commonly found in model outputs."""
                    import re

                    tool_calls = []

                    # Look for the create_security_plan function call syntax in text
                    if is_small_model:
                        # Simple pattern for create_security_plan with tasks parameter
                        pattern = r"create_security_plan\s*\(\s*tasks\s*=\s*(\[[\s\S]*?\])\s*\)"
                        match = re.search(pattern, text, re.IGNORECASE)

                        if match:
                            tasks_str = match.group(1)
                            # Try to fix common JSON issues
                            tasks_str = tasks_str.replace("'", '"')

                            try:
                                tasks = json.loads(tasks_str)
                                import hashlib

                                call_id = f"call_{hashlib.md5(tasks_str.encode()).hexdigest()[:8]}"

                                tool_calls = [
                                    {
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": "create_security_plan",
                                            "arguments": json.dumps({"tasks": tasks}),
                                        },
                                    }
                                ]
                            except json.JSONDecodeError:
                                pass

                    return tool_calls

            return OllamaWrapper(result, self.model, is_small_model, self.logger)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ollama API request failed: {str(e)}")
            raise
        except json.JSONDecodeError:
            self.logger.error("Failed to parse Ollama API response")
            raise ValueError("Invalid response from Ollama API")

    def _anthropic_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        tools: Optional[List[Dict]],
        json_mode: bool,
    ) -> Union[Dict[str, Any], Any]:
        """Generate a completion using Anthropic."""
        # Convert chat format to Anthropic format
        anthropic_messages = []

        for msg in messages:
            role = (
                "assistant"
                if msg["role"] == "assistant"
                else "user"
                if msg["role"] == "user"
                else "system"
            )
            content = msg["content"]
            anthropic_messages.append({"role": role, "content": content})

        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "temperature": temperature,
            "max_tokens": 4000,
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
                    tool_calls.append(
                        {
                            "id": tool_use.id,
                            "type": "function",  # Always include type
                            "function": {
                                "name": tool_use.name,
                                "arguments": json.dumps(tool_use.input),
                            },
                        }
                    )

                # Create a wrapper object similar to OpenAI's format for compatibility
                class CompatibilityWrapper:
                    def __init__(self, response, tool_calls):
                        self.choices = [
                            type(
                                "Choice",
                                (),
                                {
                                    "message": type(
                                        "Message",
                                        (),
                                        {
                                            "content": response.content[0].text
                                            if response.content
                                            else "",
                                            "tool_calls": tool_calls,
                                        },
                                    ),
                                    "finish_reason": response.stop_reason,
                                },
                            )
                        ]
                        self.model = response.model

                return CompatibilityWrapper(response, tool_calls)
            else:
                # No tools, simpler wrapper
                class CompatibilityWrapper:
                    def __init__(self, response):
                        self.choices = [
                            type(
                                "Choice",
                                (),
                                {
                                    "message": type(
                                        "Message",
                                        (),
                                        {
                                            "content": response.content[0].text
                                            if response.content
                                            else "",
                                            "tool_calls": [],
                                        },
                                    ),
                                    "finish_reason": response.stop_reason,
                                },
                            )
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
                "stop_sequences": ["\n\nHuman:"],
            }

            response = self.client.completion(**old_kwargs)

            # Create a simple wrapper object for old API
            class OldApiWrapper:
                def __init__(self, response, model):
                    self.choices = [
                        type(
                            "Choice",
                            (),
                            {
                                "message": type(
                                    "Message",
                                    (),
                                    {"content": response.completion, "tool_calls": []},
                                ),
                                "finish_reason": "stop",
                            },
                        )
                    ]
                    self.model = model

            return OldApiWrapper(response, self.model)

    def create_embedding(self, text: str) -> List[float]:
        """Generate embeddings for the given text."""
        if self.provider == "openai":
            response = self.client.embeddings.create(
                model="text-embedding-3-small", input=text
            )
            return response.data[0].embedding
        elif self.provider == "ollama":
            # Check if Ollama server supports embeddings
            try:
                response = requests.post(
                    f"{self.ollama_base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                )
                if response.status_code == 200:
                    return response.json().get("embedding", [])
                else:
                    self.logger.warning(
                        f"Ollama embeddings failed, falling back to OpenAI: {response.text}"
                    )
            except Exception as e:
                self.logger.warning(
                    f"Ollama embeddings error, falling back to OpenAI: {str(e)}"
                )

            # If Ollama embedding fails, fall back to OpenAI
            self.logger.info("Falling back to OpenAI for embeddings")
            fallback_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small", input=text
            )
            return response.data[0].embedding
        elif self.provider == "gemini":
            # Use Gemini for embeddings if configured
            try:
                if not self.google_api_key:
                    self.logger.warning(
                        "Google API Key not found for Gemini embeddings. Falling back to OpenAI."
                    )
                    raise ValueError(
                        "Missing Google API Key for Gemini embeddings"
                    )  # Trigger fallback

                # Read embedding model from config, fallback to default
                embedding_model_name = (
                    self.config.get("llm", {}).get("gemini", {}).get("embedding_model")
                )
                if not embedding_model_name:
                    embedding_model_name = (
                        "models/text-embedding-004"  # Hardcoded fallback model
                    )
                    self.logger.warning(
                        f"Gemini 'embedding_model' not found in config. Using default: {embedding_model_name}"
                    )

                task_type = "RETRIEVAL_DOCUMENT"  # Default task type, can be configured later if needed

                self.logger.debug(
                    f"Attempting Gemini embedding with model: {embedding_model_name}, task_type: {task_type}"
                )
                response = genai.embed_content(
                    model=embedding_model_name, content=text, task_type=task_type
                )

                if "embedding" in response:
                    self.logger.debug("Gemini embedding successful.")
                    return response["embedding"]
                else:
                    self.logger.warning(
                        "Gemini embedding response did not contain 'embedding' key. Falling back to OpenAI."
                    )
                    raise ValueError(
                        "Invalid response structure from Gemini embeddings"
                    )  # Trigger fallback

            except Exception as e:
                if google_api_exceptions and isinstance(
                    e, google_api_exceptions.GoogleAPIError
                ):
                    self.logger.error(
                        f"Gemini embedding API error: {e}. Falling back to OpenAI."
                    )
                else:
                    self.logger.error(
                        f"Unexpected error during Gemini embedding: {e}. Falling back to OpenAI."
                    )

            # Fallback to OpenAI if Gemini fails or isn't configured properly
            self.logger.info(
                "Falling back to OpenAI for embeddings due to Gemini failure or missing config."
            )
            fallback_client = OpenAI(
                api_key=self.openai_api_key
            )  # Use the key stored in self
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small", input=text
            )
            return response.data[0].embedding
        else:
            # Fallback for other providers (e.g., Anthropic) or if explicitly needed
            self.logger.info(
                f"Provider '{self.provider}' does not support embeddings or fallback triggered. Using OpenAI."
            )
            fallback_client = OpenAI(
                api_key=self.openai_api_key
            )  # Use the key stored in self
            response = fallback_client.embeddings.create(
                model="text-embedding-3-small", input=text
            )
            return response.data[0].embedding

    def _gemini_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        tools: Optional[List[Dict]],
        json_mode: bool,
    ) -> Dict[str, Any]:
        """Generate a completion using Google Gemini, converting messages."""
        self.logger.debug(f"Starting Gemini completion with {len(messages)} messages.")

        gemini_messages = []
        system_prompt = None
        first_system_prompt_processed = False
        tool_call_name_by_id: Dict[str, str] = {}

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            tool_calls = msg.get("tool_calls")
            name = msg.get("name")  # Used for tool role

            if role == "system":
                if not first_system_prompt_processed:
                    system_prompt = content
                    first_system_prompt_processed = True
                    self.logger.debug(
                        f"Captured system prompt: {system_prompt[:100]}..."
                    )  # Log first 100 chars
                else:
                    self.logger.warning(
                        "Multiple system messages found. Only the first one will be used."
                    )
                continue  # System messages are handled separately

            elif role == "user":
                if content:  # Ensure content is not None or empty
                    gemini_messages.append(
                        {"role": "user", "parts": [{"text": content}]}
                    )
                else:
                    self.logger.warning("User message with empty content skipped.")

            elif role == "assistant":
                model_parts = []
                # Handle text content
                if content:
                    model_parts.append({"text": content})

                # Handle tool calls
                if tool_calls:
                    for tool_call in tool_calls:
                        if tool_call.get("type") == "function":
                            func = tool_call.get("function", {})
                            func_name = func.get("name")
                            func_args_str = func.get("arguments")
                            tool_call_id = tool_call.get("id")
                            if func_name and func_args_str:
                                if tool_call_id:
                                    tool_call_name_by_id[tool_call_id] = func_name
                                try:
                                    arguments = json.loads(func_args_str)
                                    # Ensure arguments is a dict for Gemini
                                    if not isinstance(arguments, dict):
                                        self.logger.warning(
                                            f"Tool call arguments for {func_name} were not a dict, wrapping: {arguments}"
                                        )
                                        # Attempt to handle non-dict arguments, e.g., wrap a string
                                        if isinstance(arguments, str):
                                            arguments = {
                                                "value": arguments
                                            }  # Example wrapping
                                        else:
                                            # Fallback for other types, might need adjustment
                                            arguments = {"data": arguments}

                                    function_call = genai_types.FunctionCall(
                                        name=func_name, args=arguments
                                    )
                                    model_parts.append(
                                        genai_types.Part(function_call=function_call)
                                    )
                                    self.logger.debug(
                                        f"Added FunctionCall part for: {func_name}"
                                    )
                                except json.JSONDecodeError:
                                    self.logger.error(
                                        f"Failed to parse JSON arguments for tool call {func_name}: {func_args_str}"
                                    )
                                except Exception as e:
                                    self.logger.error(
                                        f"Error processing tool call {func_name}: {e}"
                                    )
                            else:
                                self.logger.warning(
                                    f"Skipping tool call due to missing name or arguments: {tool_call}"
                                )
                        else:
                            self.logger.warning(
                                f"Skipping non-function tool call: {tool_call}"
                            )

                if model_parts:
                    gemini_messages.append({"role": "model", "parts": model_parts})
                else:
                    # Gemini requires model messages to have parts. If an assistant message
                    # had neither content nor valid tool calls, we might skip it or log.
                    # Let's log a warning for now.
                    self.logger.warning(
                        f"Assistant message resulted in empty parts, skipping: {msg}"
                    )

            elif role == "tool":
                tool_call_id = msg.get("tool_call_id")
                resolved_name = name or tool_call_name_by_id.get(tool_call_id)
                if resolved_name and content:
                    try:
                        # Assumption: content is the result string. Wrap it in a dict.
                        # Adapt this if VibePenTester provides results differently.
                        response_data = {"result": content}  # Wrap string content
                        # If content is already a dict, you might use it directly:
                        # try:
                        #     response_data = json.loads(content)
                        #     if not isinstance(response_data, dict):
                        #         response_data = {'result': content} # Fallback if not dict
                        # except json.JSONDecodeError:
                        #      response_data = {'result': content} # Fallback if not JSON

                        function_response = genai_types.FunctionResponse(
                            name=resolved_name, response=response_data
                        )
                        part = genai_types.Part(function_response=function_response)
                        # Tool responses are added as 'user' role messages in Gemini
                        gemini_messages.append({"role": "user", "parts": [part]})
                        self.logger.debug(
                            f"Added FunctionResponse part for tool: {resolved_name}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Error processing tool result for {resolved_name}: {e}"
                        )
                elif content:
                    fallback_id = tool_call_id or "unknown_tool_call"
                    gemini_messages.append(
                        {
                            "role": "user",
                            "parts": [
                                {"text": f"Tool result ({fallback_id}): {content}"}
                            ],
                        }
                    )
                    self.logger.warning(
                        f"Tool message missing name; added text fallback for {fallback_id}"
                    )
                else:
                    self.logger.warning(
                        f"Skipping tool message due to missing content: {msg}"
                    )

            else:
                self.logger.warning(f"Unsupported message role encountered: {role}")

        # Handle System Prompt Prepending
        if system_prompt:
            first_user_idx = -1
            for i, msg in enumerate(gemini_messages):
                if msg["role"] == "user":
                    # Check if the first part is text (it should be for a normal user message)
                    if (
                        msg.get("parts")
                        and isinstance(msg["parts"], list)
                        and len(msg["parts"]) > 0
                        and "text" in msg["parts"][0]
                    ):
                        first_user_idx = i
                        break
                    else:
                        # Found a user message, but it's not a simple text message (e.g., FunctionResponse)
                        # We should insert the system prompt *before* this complex user message.
                        self.logger.debug(
                            "Found non-text user message first, inserting system prompt before it."
                        )
                        gemini_messages.insert(
                            i, {"role": "user", "parts": [{"text": system_prompt}]}
                        )
                        system_prompt = None  # Mark as handled
                        break

            if (
                first_user_idx != -1 and system_prompt
            ):  # Check system_prompt again in case it was handled above
                original_text = gemini_messages[first_user_idx]["parts"][0].get(
                    "text", ""
                )
                # Ensure parts list and first part exist before modification
                if (
                    gemini_messages[first_user_idx].get("parts")
                    and len(gemini_messages[first_user_idx]["parts"]) > 0
                ):
                    gemini_messages[first_user_idx]["parts"][0]["text"] = (
                        f"{system_prompt}\n\n{original_text}"
                    )
                    self.logger.debug(
                        f"Prepended system prompt to first user message at index {first_user_idx}."
                    )
                else:
                    self.logger.error(
                        f"Could not prepend system prompt: First user message at index {first_user_idx} has invalid parts structure."
                    )

            elif (
                system_prompt
            ):  # No user message found at all, or first user wasn't text
                # If system_prompt is still not None here, it means no suitable user message was found to prepend to.
                # Insert the system prompt as the very first message.
                gemini_messages.insert(
                    0, {"role": "user", "parts": [{"text": system_prompt}]}
                )
                self.logger.debug(
                    "No suitable user message found, inserting system prompt as the first message."
                )

        # Optional: Check for role alternation (Gemini requires user/model alternation)
        last_role = None
        for i, msg in enumerate(gemini_messages):
            current_role = msg.get("role")
            if current_role == last_role:
                self.logger.warning(
                    f"Gemini message role alternation violation at index {i}: {last_role} -> {current_role}"
                )
            last_role = current_role

        # Log the final structure before making the API call (or returning placeholder)
        try:
            # Use default=str for non-serializable objects like genai_types parts
            self.logger.debug(
                f"Final Gemini messages structure:\n{json.dumps(gemini_messages, indent=2, default=str)}"
            )
        except Exception as e:
            self.logger.error(
                f"Error serializing final Gemini messages for logging: {e}"
            )
            self.logger.debug(f"Final Gemini messages (raw): {gemini_messages}")

        # --- Tool Conversion Logic (OpenAI format to Gemini format) ---
        gemini_tools = None
        if tools:
            declarations = []
            for tool in tools:
                if tool.get("type") == "function":
                    function_data = tool.get("function", {})
                    name = function_data.get("name")
                    description = function_data.get("description", "")
                    # Parameters should follow OpenAPI Schema
                    parameters = function_data.get("parameters")

                    if name:
                        try:
                            # Ensure parameters is a dict or None, as expected by FunctionDeclaration
                            if parameters is not None and not isinstance(
                                parameters, dict
                            ):
                                self.logger.warning(
                                    f"Tool '{name}' parameters are not a dict, attempting to use as is: {type(parameters)}"
                                )
                                # Depending on strictness, you might want to raise an error or skip
                                # For now, let's pass it along, Gemini might handle it or error out.

                            declaration = genai_types.FunctionDeclaration(
                                name=name,
                                description=description,
                                parameters=parameters,  # Pass the parameters dict directly
                            )
                            declarations.append(declaration)
                            self.logger.debug(
                                f"Created FunctionDeclaration for tool: {name}"
                            )
                        except Exception as e:
                            # Catch potential errors during FunctionDeclaration creation
                            self.logger.error(
                                f"Error creating FunctionDeclaration for tool '{name}': {e}"
                            )
                    else:
                        self.logger.warning(
                            f"Skipping tool due to missing 'name' in function data: {function_data}"
                        )
                else:
                    self.logger.warning(
                        f"Skipping tool with unsupported type '{tool.get('type')}': {tool}"
                    )

            if declarations:
                gemini_tools = [genai_types.Tool(function_declarations=declarations)]
                try:
                    # Log the structure safely using to_dict if available, otherwise raw
                    if hasattr(genai_types.Tool, "to_dict"):
                        self.logger.debug(
                            f"Generated Gemini tools structure: {json.dumps(genai_types.Tool.to_dict(gemini_tools[0]), indent=2, default=str)}"
                        )
                    else:
                        self.logger.debug(
                            f"Generated Gemini tools structure (raw): {gemini_tools}"
                        )
                except Exception as e:
                    self.logger.error(
                        f"Error serializing Gemini tools for logging: {e}"
                    )
                    self.logger.debug(f"Generated Gemini tools (raw): {gemini_tools}")
        # --- End Tool Conversion ---

        # --- Actual API Call and Response Handling ---
        # Determine effective temperature based on parameter and config defaults
        effective_temperature = temperature  # Start with the parameter value
        if (
            effective_temperature is None
        ):  # Check if a specific temp was NOT passed via parameter
            # Use self.config loaded in __init__
            gemini_config = self.config.get("llm", {}).get("gemini", {})
            default_temp = gemini_config.get("temperature")
            if isinstance(
                default_temp, (float, int)
            ):  # Check if config temp is valid number
                effective_temperature = float(default_temp)
                self.logger.debug(
                    f"Using default Gemini temperature from config: {effective_temperature}"
                )
            else:
                effective_temperature = (
                    0.7  # Hardcoded fallback if config is missing/invalid
                )
                self.logger.debug(
                    f"Using hardcoded fallback temperature: {effective_temperature}"
                )
        else:
            # Ensure the provided temperature is a float if it's not None
            try:
                effective_temperature = float(temperature)
                self.logger.debug(
                    f"Using provided temperature: {effective_temperature}"
                )
            except (ValueError, TypeError):
                self.logger.warning(
                    f"Invalid temperature parameter '{temperature}' provided. Using fallback 0.7."
                )
                effective_temperature = 0.7  # Fallback if provided value is invalid

        generation_config = genai_types.GenerationConfig(
            temperature=effective_temperature
        )  # Use the determined effective_temperature
        # Add other config options if needed, e.g., max_output_tokens

        api_kwargs = {
            "contents": gemini_messages,
            "generation_config": generation_config,
        }
        if gemini_tools:
            api_kwargs["tools"] = gemini_tools

        output = {"content": None, "tool_calls": []}  # Initialize output structure

        try:
            self.logger.debug(f"Calling Gemini API with model {self.model}...")
            response = self.gemini_model.generate_content(**api_kwargs)
            self.logger.debug("Gemini API response received.")

            # Enhanced Response Parsing (Text and Function Calls)
            if response and response.candidates:
                # Process parts from the first candidate
                candidate = response.candidates[0]
                if hasattr(candidate, "content") and hasattr(
                    candidate.content, "parts"
                ):
                    parts = candidate.content.parts
                    self.logger.debug(f"Response parts found: {len(parts)}")
                    for part in parts:
                        # Check for text content
                        if hasattr(part, "text") and part.text:
                            output["content"] = (
                                output["content"] or ""
                            ) + part.text  # Concatenate text parts
                            self.logger.debug(
                                f"Appended text content (current total length: {len(output['content'])})"
                            )

                        # Check for function call
                        if hasattr(part, "function_call") and part.function_call:
                            fc = part.function_call
                            call_id = (
                                f"gemini_call_{uuid.uuid4()}"  # Generate unique ID
                            )
                            name = fc.name
                            self.logger.debug(
                                f"Found function call: {name} (ID: {call_id})"
                            )

                            # Ensure fc.args is treated as a dictionary-like object before dumping to JSON
                            arguments_dict = {}
                            if hasattr(fc, "args"):
                                # Convert proto MapComposite/RepeatedComposite to Python dict/list
                                def _convert_proto_to_py(value):
                                    if hasattr(
                                        value, "items"
                                    ):  # Check for MapComposite (dict-like)
                                        return {
                                            k: _convert_proto_to_py(v)
                                            for k, v in value.items()
                                        }
                                    elif hasattr(value, "__iter__") and not isinstance(
                                        value, (str, bytes, dict)
                                    ):  # Check for RepeatedComposite (list-like)
                                        return [
                                            _convert_proto_to_py(item) for item in value
                                        ]
                                    # Handle primitive types directly (string, number, bool, null)
                                    # This might need adjustment based on actual primitive types returned by the API
                                    elif isinstance(
                                        value, (str, int, float, bool, type(None))
                                    ):
                                        return value
                                    else:
                                        # Fallback for unexpected types
                                        self.logger.warning(
                                            f"Unexpected type in Gemini args conversion: {type(value)}, value: {value}"
                                        )
                                        return str(
                                            value
                                        )  # Convert to string as a fallback

                                try:
                                    arguments_dict = _convert_proto_to_py(fc.args)
                                    self.logger.debug(
                                        f"Converted Gemini function call args: {arguments_dict}"
                                    )
                                except Exception as conv_e:
                                    self.logger.error(
                                        f"Error converting Gemini function call args: {conv_e}",
                                        exc_info=True,
                                    )
                                    arguments_dict = {}  # Fallback

                            # Convert arguments dictionary to JSON string
                            try:
                                # Now arguments_dict should be a standard Python dict/list structure
                                arguments_str = json.dumps(arguments_dict)
                                self.logger.debug(
                                    f"Serialized function call arguments to JSON string: {arguments_str}"
                                )
                            except TypeError as e:
                                self.logger.error(
                                    f"Failed to serialize function call arguments to JSON: {e}. Args dict: {arguments_dict}",
                                    exc_info=True,
                                )
                                arguments_str = (
                                    "{}"  # Fallback to empty JSON object string
                                )

                            # Create the standardized tool call structure
                            tool_call = {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": arguments_str,  # Store as JSON string
                                },
                            }
                            output["tool_calls"].append(tool_call)
                            self.logger.debug(
                                f"Appended tool call to output: {tool_call}"
                            )
                else:
                    self.logger.warning(
                        "Gemini response candidate missing 'content' or 'parts' attribute."
                    )

            else:
                # Handle cases where response might not have candidates (e.g., safety filters)
                if hasattr(response, "prompt_feedback") and response.prompt_feedback:
                    self.logger.warning(
                        f"Gemini response blocked or missing candidates. Feedback: {response.prompt_feedback}"
                    )
                    # Return a specific structure indicating blockage
                    output["content"] = (
                        f"Error: Response blocked by safety settings. Feedback: {response.prompt_feedback}"
                    )
                else:
                    self.logger.warning("Gemini response missing or has no candidates.")

            # Log the final parsed output structure (or parts of it)
            self.logger.debug(
                f"Gemini completion successful. Parsed output: { {k: (v[:100] + '...' if isinstance(v, str) and len(v) > 100 else v) for k, v in output.items()} }"
            )  # Log truncated content
            return output

        except Exception as e:
            if google_api_exceptions and isinstance(
                e, google_api_exceptions.GoogleAPIError
            ):
                self.logger.error(f"Gemini API call failed: {e}", exc_info=True)
            else:
                # Catch any other unexpected errors during the process
                self.logger.error(
                    f"Gemini processing failed unexpectedly: {e}", exc_info=True
                )
            raise  # Re-raise the caught exception
