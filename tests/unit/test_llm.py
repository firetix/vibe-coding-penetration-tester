# tests/unit/test_llm.py
import os
import pytest
import json # <-- Added import
from unittest.mock import patch, MagicMock, call, ANY # <-- Added ANY import
import google.api_core.exceptions # Added for Gemini error testing

from core.llm import LLMProvider


@pytest.fixture
def mock_openai_response():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message = MagicMock()
    mock_response.choices[0].message.content = "This is a test response"
    mock_response.choices[0].message.tool_calls = None
    mock_response.choices[0].finish_reason = "stop"
    mock_response.model = "gpt-4o"
    return mock_response


@pytest.fixture
def mock_anthropic_response():
    mock_response = MagicMock()
    mock_response.content = [MagicMock()]
    mock_response.content[0].text = "This is a test response"
    mock_response.tool_uses = None
    mock_response.stop_reason = "stop"
    mock_response.model = "claude-3-5-sonnet"
    return mock_response


class TestLLMProvider:

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")  # Patch the import in core.llm, not openai directly
    def test_openai_initialization(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Act
        provider = LLMProvider(provider="openai", model="gpt-4o")

        # Assert
        assert provider.provider == "openai"
        assert provider.model == "gpt-4o"
        assert provider.client == mock_client
        mock_openai.assert_called_once_with(api_key="test_key")

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test_key"})
    @patch("core.llm.anthropic.Anthropic")  # Patch the import in core.llm
    def test_anthropic_initialization(self, mock_anthropic):
        # Arrange
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        # Act
        provider = LLMProvider(provider="anthropic", model="claude-3-opus")

        # Assert
        assert provider.provider == "anthropic"
        assert provider.model == "claude-3-opus"
        assert provider.client == mock_client
        mock_anthropic.assert_called_once_with(api_key="test_key")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_invalid_provider(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Act & Assert
        with pytest.raises(ValueError, match="Unsupported provider"):
            LLMProvider(provider="invalid_provider")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_openai_chat_completion(self, mock_openai, mock_openai_response):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_openai_response

        provider = LLMProvider(provider="openai", model="gpt-4o")

        messages = [{"role": "user", "content": "Hello"}]

        # Act
        result = provider.chat_completion(messages)

        # Assert
        # Simulate the structure returned by the wrapper/actual call
        assert result.choices[0].message.content == "This is a test response"
        assert result.choices[0].finish_reason == "stop"
        assert result.model == "gpt-4o"
        mock_client.chat.completions.create.assert_called_once()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test_key"})
    @patch("core.llm.anthropic.Anthropic")
    def test_anthropic_chat_completion(self, mock_anthropic, mock_anthropic_response):
        # Arrange
        mock_client = MagicMock()
        # Mock the new client structure
        mock_client.messages.create.return_value = mock_anthropic_response
        mock_anthropic.return_value = mock_client

        provider = LLMProvider(provider="anthropic", model="claude-3-5-sonnet")

        messages = [{"role": "user", "content": "Hello"}]

        # Act
        result = provider.chat_completion(messages)

        # Assert
        # Check the structure returned by the CompatibilityWrapper
        assert result.choices[0].message.content == "This is a test response"
        assert result.choices[0].finish_reason == "stop"
        assert result.model == "claude-3-5-sonnet"
        mock_client.messages.create.assert_called_once()


    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_openai_chat_completion_with_tools(self, mock_openai, mock_openai_response):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Create a proper mock for tool calls
        tool_call_mock = MagicMock()
        tool_call_mock.id = "call_123"
        tool_call_mock.type = "function"
        tool_call_mock.function = MagicMock()
        tool_call_mock.function.name = "test_function"
        tool_call_mock.function.arguments = '{"arg1": "value1"}'

        # Create a custom MagicMock with specific return values for the tool calls
        def create_tool_call_response(mock_response):
            # Create a new instance of the response
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message = MagicMock()
            response.choices[0].message.content = None
            response.choices[0].finish_reason = "tool_calls"
            response.model = "gpt-4o"

            # Set up tool calls using the mock object
            response.choices[0].message.tool_calls = [tool_call_mock]
            return response

        mock_client.chat.completions.create.return_value = create_tool_call_response(mock_openai_response)

        provider = LLMProvider(provider="openai", model="gpt-4o")

        messages = [{"role": "user", "content": "Hello"}]
        tools = [{"type": "function", "function": {"name": "test_function", "parameters": {}}}]

        # Act
        result = provider.chat_completion(messages, tools=tools)

        # Assert
        assert result.choices[0].message.content is None
        assert result.choices[0].message.tool_calls is not None
        assert isinstance(result.choices[0].message.tool_calls, list)
        assert len(result.choices[0].message.tool_calls) > 0
        assert result.choices[0].message.tool_calls[0].id == "call_123"
        assert result.choices[0].message.tool_calls[0].function.name == "test_function"
        mock_client.chat.completions.create.assert_called_once()


    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_create_embedding(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        mock_embedding_response = MagicMock()
        mock_embedding_response.data = [MagicMock()]
        mock_embedding_response.data[0].embedding = [0.1, 0.2, 0.3]

        mock_client.embeddings.create.return_value = mock_embedding_response

        provider = LLMProvider(provider="openai", model="gpt-4o")

        # Act
        result = provider.create_embedding("Test text")

        # Assert
        assert result == [0.1, 0.2, 0.3]
        mock_client.embeddings.create.assert_called_once_with(
            model="text-embedding-3-small",
            input="Test text"
        )

    # --- Gemini Tests ---

    @patch('core.llm.genai')
    @patch('core.llm.os.getenv', return_value=None) # Ensure env var is not used
    def test_gemini_initialization_with_key(self, mock_getenv, mock_genai):
        # Arrange
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        test_api_key = "explicit_gemini_key"
        expected_model_name = "gemini-2.0-flash-thinking-exp-01-21" # Hardcoded for now

        # Act
        provider = LLMProvider(provider="gemini", google_api_key=test_api_key)

        # Assert
        assert provider.provider == "gemini"
        assert provider.google_api_key == test_api_key
        assert provider.model == expected_model_name
        assert provider.gemini_model == mock_model
        mock_genai.configure.assert_called_once_with(api_key=test_api_key)
        mock_genai.GenerativeModel.assert_called_once_with(expected_model_name)
        # When an explicit key is provided, os.getenv("GOOGLE_API_KEY") should NOT be called due to short-circuiting.
        # We only need to ensure the other keys might have been checked via getenv.
        # No specific assertion needed here for the GOOGLE_API_KEY getenv call in this test case.

    @patch('core.llm.genai')
    @patch.dict(os.environ, {"GOOGLE_API_KEY": "test_env_key"})
    def test_gemini_initialization_with_env_var(self, mock_genai):
        # Arrange
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        expected_model_name = "gemini-2.0-flash-thinking-exp-01-21"

        # Act
        provider = LLMProvider(provider="gemini") # No explicit key

        # Assert
        assert provider.provider == "gemini"
        assert provider.google_api_key == "test_env_key"
        assert provider.model == expected_model_name
        assert provider.gemini_model == mock_model
        mock_genai.configure.assert_called_once_with(api_key="test_env_key")
        mock_genai.GenerativeModel.assert_called_once_with(expected_model_name)

    @patch('core.llm.genai')
    @patch('core.llm.os.getenv', return_value=None) # Mock getenv to return None
    def test_gemini_initialization_no_key(self, mock_getenv, mock_genai):
        # Arrange (No key provided explicitly or via env)

        # Act & Assert
        with pytest.raises(ValueError, match="Google API Key not found"):
            LLMProvider(provider="gemini")

        mock_genai.configure.assert_not_called()
        mock_genai.GenerativeModel.assert_not_called()
        # Check that getenv was called for GOOGLE_API_KEY among others
        # from unittest.mock import call # Already imported at top
        assert call("GOOGLE_API_KEY") in mock_getenv.call_args_list

    @patch('core.llm.genai')
    @patch.dict(os.environ, {"GOOGLE_API_KEY": "test_key"}) # Need key for init
    @patch('core.llm.LLMProvider._gemini_completion') # Patch the target method
    def test_gemini_chat_completion_routes(self, mock_gemini_completion, mock_genai):
        # Arrange
        # Mock genai configure and model init to avoid errors during LLMProvider instantiation
        mock_model_instance = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model_instance

        provider = LLMProvider(provider="gemini")
        # Define return value for the mocked method to match expected structure
        mock_gemini_completion.return_value = {"choices": [{"message": {"content": "mocked gemini response", "tool_calls": []}, "finish_reason": "stop"}], "model": "gemini-model"} # Match structure

        messages = [{"role": "user", "content": "Hello Gemini"}]
        temperature = 0.5
        tools = None
        json_mode = False

        # Act
        result = provider.chat_completion(messages, temperature, tools, json_mode)

        # Assert
        mock_gemini_completion.assert_called_once_with(messages, temperature, tools, json_mode)
        # Check the structure returned by the mocked method
        assert result["choices"][0]["message"]["content"] == "mocked gemini response" # Adjusted assertion
        assert result["choices"][0]["message"]["tool_calls"] == []
        # Ensure genai was configured during init
        mock_genai.configure.assert_called_once_with(api_key="test_key")
        mock_genai.GenerativeModel.assert_called_once()


    # --- Gemini Message Conversion Tests ---

    @pytest.fixture
    def gemini_provider(self):
        """Fixture to create a Gemini LLMProvider with mocks."""
        with patch('core.llm.genai') as mock_genai, \
             patch.dict(os.environ, {"GOOGLE_API_KEY": "test_key"}):
            mock_model_instance = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model_instance
            provider = LLMProvider(provider="gemini")
            # Reset mocks for genai calls made during init
            mock_genai.reset_mock()
            return provider, mock_genai # Return mock_genai too if needed

    @patch('core.llm.genai_types') # Mock the types used within the method
    def test_gemini_message_conversion_simple_user(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [{"role": "user", "content": "Hello there"}]
        expected_gemini_messages = [{'role': 'user', 'parts': [{'text': 'Hello there'}]}]

        # Act
        # Directly call the protected method for unit testing
        # We rely on the debug log added in the implementation to verify the structure
        # Let's refine this: We'll mock the logger to capture the output.
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                # Check if the first argument of the call is a string and starts with the prefix
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break # Found the log message

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            # Re-parse the logged JSON to compare structures
            logged_gemini_messages = json.loads(logged_data_str)
            assert logged_gemini_messages == expected_gemini_messages

            mock_genai_types.FunctionCall.assert_not_called()
            mock_genai_types.FunctionResponse.assert_not_called()

    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_system_prompt(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [
            {"role": "system", "content": "Be helpful."},
            {"role": "user", "content": "Hello there"}
        ]
        expected_gemini_messages = [
            {'role': 'user', 'parts': [{'text': "Be helpful.\n\nHello there"}]}
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            logged_gemini_messages = json.loads(logged_data_str)
            assert logged_gemini_messages == expected_gemini_messages

    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_multiple_system_prompts(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [
            {"role": "system", "content": "Be helpful."},
            {"role": "user", "content": "Hello there"},
            {"role": "system", "content": "Be concise."} # Second system prompt
        ]
        # Only the first system prompt should be used
        expected_gemini_messages = [
            {'role': 'user', 'parts': [{'text': "Be helpful.\n\nHello there"}]}
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug, \
             patch.object(provider.logger, 'warning') as mock_logger_warning:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            logged_gemini_messages = json.loads(logged_data_str)
            assert logged_gemini_messages == expected_gemini_messages

            # Check if the warning for multiple system messages was logged
            mock_logger_warning.assert_any_call("Multiple system messages found. Only the first one will be used.")


    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_assistant_text(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi user!"}
        ]
        expected_gemini_messages = [
            {'role': 'user', 'parts': [{'text': 'Hello'}]},
            {'role': 'model', 'parts': [{'text': 'Hi user!'}]}
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            logged_gemini_messages = json.loads(logged_data_str)
            assert logged_gemini_messages == expected_gemini_messages

    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_assistant_tool_call(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_function_call_part = MagicMock()
        mock_genai_types.Part.return_value = mock_function_call_part
        tool_args = {"query": "weather"}
        messages = [
            {"role": "user", "content": "Search?"},
            {"role": "assistant", "tool_calls": [
                {"type": "function", "function": {"name": "search_tool", "arguments": json.dumps(tool_args)}}
            ]}
        ]
        expected_gemini_messages = [
            {'role': 'user', 'parts': [{'text': 'Search?'}]},
            {'role': 'model', 'parts': [mock_function_call_part]} # Expect the mocked Part object
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False) # Tools arg not needed for conversion test

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            # Parse the JSON structure
            logged_gemini_messages = json.loads(logged_data_str)

            # Assert structure
            assert len(logged_gemini_messages) == 2
            assert logged_gemini_messages[0]['role'] == 'user'
            assert logged_gemini_messages[0]['parts'][0]['text'] == 'Search?'
            assert logged_gemini_messages[1]['role'] == 'model'
            # We know the parts list contains the mock object, which gets stringified.
            # Check that there is one part. The specific call is checked below.
            assert len(logged_gemini_messages[1]['parts']) == 1

            # Check genai_types calls (these remain the most reliable way to check mock interactions)
            mock_genai_types.FunctionCall.assert_called_once_with(name="search_tool", args=tool_args)
            mock_genai_types.Part.assert_called_once_with(function_call=mock_genai_types.FunctionCall.return_value)
            mock_genai_types.FunctionResponse.assert_not_called()


    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_assistant_text_and_tool_call(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_function_call_part = MagicMock(name="FunctionCallPart")
        # Make Part return different mocks based on input
        def part_side_effect(*args, **kwargs):
            if kwargs.get('function_call'):
                return mock_function_call_part
            # We don't expect FunctionResponse here, but good practice
            # elif kwargs.get('function_response'):
            #     return mock_function_response_part
            else:
                # Fallback for unexpected calls
                return MagicMock()
        mock_genai_types.Part.side_effect = part_side_effect

        tool_args = {"param": "value"}
        messages = [
            {"role": "user", "content": "Do something"},
            {"role": "assistant", "content": "Okay, using a tool.", "tool_calls": [
                {"type": "function", "function": {"name": "do_it", "arguments": json.dumps(tool_args)}}
            ]}
        ]
        # Expected parts: one text, one function call part
        expected_model_parts_structure = [{'text': 'Okay, using a tool.'}, mock_function_call_part]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert structure primarily by checking mock calls

            mock_genai_types.FunctionCall.assert_called_once_with(name="do_it", args=tool_args)
            # Part should be called once for the function call
            mock_genai_types.Part.assert_called_once_with(function_call=mock_genai_types.FunctionCall.return_value)


    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_tool_result(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_function_call_part = MagicMock(name="FunctionCallPart")
        mock_function_response_part = MagicMock(name="FunctionResponsePart")

        # Make Part return different mocks based on input
        def part_side_effect(*args, **kwargs):
            if kwargs.get('function_call'):
                return mock_function_call_part
            elif kwargs.get('function_response'):
                 return mock_function_response_part
            else:
                return MagicMock()
        mock_genai_types.Part.side_effect = part_side_effect


        tool_name = "search_tool"
        tool_result_content = "Found results."
        # Gemini expects response as a dict
        expected_response_data = {'result': tool_result_content}

        messages = [
            # Need preceding messages for context, otherwise tool result is invalid
            {"role": "user", "content": "Search?"},
            {"role": "assistant", "tool_calls": [
                {"type": "function", "function": {"name": tool_name, "arguments": "{}"}}
            ]},
            {"role": "tool", "name": tool_name, "content": tool_result_content}
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert structure primarily by checking mock calls

            # Check genai_types calls
            mock_genai_types.FunctionCall.assert_called_once_with(name=tool_name, args={}) # Arguments was "{}" -> {}
            mock_genai_types.FunctionResponse.assert_called_once_with(name=tool_name, response=expected_response_data)
            # Part called once for FunctionCall, once for FunctionResponse
            assert mock_genai_types.Part.call_count == 2
            mock_genai_types.Part.assert_any_call(function_call=mock_genai_types.FunctionCall.return_value)
            mock_genai_types.Part.assert_any_call(function_response=mock_genai_types.FunctionResponse.return_value)


    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_system_prompt_no_user(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [
            {"role": "system", "content": "Be helpful."},
            # No user message
            {"role": "assistant", "content": "Okay"}
        ]
        # System prompt should become the first user message
        expected_gemini_messages = [
            {'role': 'user', 'parts': [{'text': "Be helpful."}]},
            {'role': 'model', 'parts': [{'text': 'Okay'}]}
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_args in mock_logger_debug.call_args_list:
                if call_args.args and isinstance(call_args.args[0], str) and call_args.args[0].startswith(json_prefix):
                    logged_message_full = call_args.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}'"

            logged_gemini_messages = json.loads(logged_data_str)
            assert logged_gemini_messages == expected_gemini_messages

    @patch('core.llm.genai_types')
    def test_gemini_message_conversion_system_prompt_before_function_response(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_function_response_part = MagicMock(name="FunctionResponsePart")
        mock_genai_types.Part.return_value = mock_function_response_part

        tool_name = "get_info"
        tool_result_content = '{"info": "details"}'
        expected_response_data = {'result': tool_result_content} # Still wrap string

        messages = [
            {"role": "system", "content": "System instruction."},
            # No direct user message after system, only tool result which becomes user role
            {"role": "tool", "name": tool_name, "content": tool_result_content}
        ]

        # System prompt should be inserted as a new user message *before* the tool result user message
        expected_gemini_messages_structure = [
            {'role': 'user', 'parts': [{'text': "System instruction."}]},
            {'role': 'user', 'parts': [mock_function_response_part]} # Tool result
        ]

        # Act & Assert
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages, 0.7, None, False)

            # Assert - Find the specific debug call logging the final structure
            json_prefix = "Final Gemini messages structure:\n"
            logged_data_str = None
            for call_info in mock_logger_debug.call_args_list:
                # Check if the first argument of the call is a string and starts with the prefix
                if call_info.args and isinstance(call_info.args[0], str) and call_info.args[0].startswith(json_prefix):
                    logged_message_full = call_info.args[0]
                    logged_data_str = logged_message_full[len(json_prefix):]
                    break # Found the log message

            assert logged_data_str is not None, f"Could not find log message starting with '{json_prefix}' in calls: {mock_logger_debug.call_args_list}"

            # Parse the JSON structure
            logged_gemini_messages = json.loads(logged_data_str)

            # Assert structure
            # Check the overall structure based on expected_gemini_messages_structure
            assert len(logged_gemini_messages) == len(expected_gemini_messages_structure)
            assert logged_gemini_messages[0]['role'] == expected_gemini_messages_structure[0]['role']
            assert logged_gemini_messages[0]['parts'] == expected_gemini_messages_structure[0]['parts']
            assert logged_gemini_messages[1]['role'] == expected_gemini_messages_structure[1]['role']
            # We can't directly compare the mock part after JSON parsing, rely on FunctionResponse check below

            # Ensure the FunctionResponse was created correctly before being added to parts
            mock_genai_types.FunctionResponse.assert_called_once_with(name=tool_name, response=expected_response_data)
            # Ensure the Part containing the FunctionResponse was created
            mock_genai_types.Part.assert_called_with(function_response=mock_genai_types.FunctionResponse.return_value)
# --- Gemini Tool Conversion Tests ---

    @patch('core.llm.genai_types')
    def test_gemini_tool_conversion_basic(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_declaration = MagicMock(name="MockDeclaration")
        mock_genai_types.FunctionDeclaration.return_value = mock_declaration
        mock_tool = MagicMock(name="MockTool")
        mock_genai_types.Tool.return_value = mock_tool

        openai_tool = {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather",
                "parameters": {
                    "type": "object",
                    "properties": {"location": {"type": "string"}},
                    "required": ["location"]
                }
            }
        }
        openai_tools = [openai_tool]

        # Act
        with patch.object(provider.logger, 'debug') as mock_logger_debug:
            provider._gemini_completion(messages=[], temperature=0.7, tools=openai_tools, json_mode=False)

        # Assert
        mock_genai_types.FunctionDeclaration.assert_called_once_with(
            name="get_weather",
            description="Get the current weather",
            parameters=openai_tool["function"]["parameters"]
        )
        mock_genai_types.Tool.assert_called_once_with(
            function_declarations=[mock_declaration]
        )
        # Check if the debug log for generated tools was called
        assert any("Generated Gemini tools structure" in call.args[0] for call in mock_logger_debug.call_args_list), "Tool structure debug log not found"


    @patch('core.llm.genai_types')
    def test_gemini_tool_conversion_multiple(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_declaration1 = MagicMock(name="MockDeclaration1")
        mock_declaration2 = MagicMock(name="MockDeclaration2")
        mock_genai_types.FunctionDeclaration.side_effect = [mock_declaration1, mock_declaration2]
        mock_tool = MagicMock(name="MockTool")
        mock_genai_types.Tool.return_value = mock_tool

        openai_tools = [
            {
                "type": "function",
                "function": {"name": "tool_one", "description": "First tool", "parameters": {"type": "object"}}
            },
            {
                "type": "function",
                "function": {"name": "tool_two", "description": "Second tool", "parameters": None} # Test None parameters
            }
        ]

        # Act
        provider._gemini_completion(messages=[], temperature=0.7, tools=openai_tools, json_mode=False)

        # Assert
        assert mock_genai_types.FunctionDeclaration.call_count == 2
        mock_genai_types.FunctionDeclaration.assert_has_calls([
            call(name="tool_one", description="First tool", parameters={"type": "object"}),
            call(name="tool_two", description="Second tool", parameters=None)
        ], any_order=False) # Order should be preserved

        mock_genai_types.Tool.assert_called_once_with(
            function_declarations=[mock_declaration1, mock_declaration2]
        )

    @patch('core.llm.genai_types')
    def test_gemini_tool_conversion_none_or_empty(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider

        # Act & Assert for None
        provider._gemini_completion(messages=[], temperature=0.7, tools=None, json_mode=False)
        mock_genai_types.FunctionDeclaration.assert_not_called()
        mock_genai_types.Tool.assert_not_called()

        # Reset mocks
        mock_genai_types.FunctionDeclaration.reset_mock()
        mock_genai_types.Tool.reset_mock()

        # Act & Assert for Empty List
        provider._gemini_completion(messages=[], temperature=0.7, tools=[], json_mode=False)
        mock_genai_types.FunctionDeclaration.assert_not_called()
        mock_genai_types.Tool.assert_not_called()


    @patch('core.llm.genai_types')
    def test_gemini_tool_conversion_non_function(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        mock_declaration = MagicMock(name="MockDeclaration")
        mock_genai_types.FunctionDeclaration.return_value = mock_declaration
        mock_tool = MagicMock(name="MockTool")
        mock_genai_types.Tool.return_value = mock_tool

        openai_tools = [
            {"type": "code_interpreter"}, # Non-function tool
            {
                "type": "function",
                "function": {"name": "real_function", "description": "A real one", "parameters": {}}
            }
        ]

        # Act
        with patch.object(provider.logger, 'warning') as mock_logger_warning:
             provider._gemini_completion(messages=[], temperature=0.7, tools=openai_tools, json_mode=False)

        # Assert
        # Only the 'function' type tool should lead to a declaration
        mock_genai_types.FunctionDeclaration.assert_called_once_with(
            name="real_function",
            description="A real one",
            parameters={}
        )
        mock_genai_types.Tool.assert_called_once_with(
            function_declarations=[mock_declaration]
        )
        # Check warning log
        mock_logger_warning.assert_any_call("Skipping tool with unsupported type 'code_interpreter': {'type': 'code_interpreter'}")


    @patch('core.llm.genai_types')
    def test_gemini_tool_conversion_missing_name(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider

        openai_tools = [
            {
                "type": "function",
                "function": {"description": "Tool missing name", "parameters": {}} # Missing 'name'
            },
             {
                "type": "function",
                "function": {"name": "good_tool", "description": "This one is okay", "parameters": {}}
            }
        ]
        mock_declaration = MagicMock(name="MockDeclarationGood")
        mock_genai_types.FunctionDeclaration.return_value = mock_declaration # Only called for the good one
        mock_tool = MagicMock(name="MockTool")
        mock_genai_types.Tool.return_value = mock_tool


        # Act
        with patch.object(provider.logger, 'warning') as mock_logger_warning:
            provider._gemini_completion(messages=[], temperature=0.7, tools=openai_tools, json_mode=False)

        # Assert
        # FunctionDeclaration should only be called for the tool with a name
        mock_genai_types.FunctionDeclaration.assert_called_once_with(
             name="good_tool",
             description="This one is okay",
             parameters={}
        )
        # Tool should be created with only the valid declaration
        mock_genai_types.Tool.assert_called_once_with(
            function_declarations=[mock_declaration]
        )
        # Check warning log for the skipped tool
        mock_logger_warning.assert_any_call("Skipping tool due to missing 'name' in function data: {'description': 'Tool missing name', 'parameters': {}}")


    # --- Gemini API Call & Response Handling Tests ---

    @patch('core.llm.genai_types')
    def test_gemini_completion_api_call_text_response(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [{"role": "user", "content": "Hello"}]
        temperature = 0.8
        expected_output = {"content": "Mock Response Text", "tool_calls": []}

        # Mock the GenerationConfig
        mock_config = MagicMock()
        mock_genai_types.GenerationConfig.return_value = mock_config

        # Mock the API response structure
        mock_api_response = MagicMock()
        mock_part = MagicMock()
        mock_part.text = "Mock Response Text"
        # Ensure 'function_call' attribute does not exist or is None for text part
        del mock_part.function_call # Or mock_part.function_call = None

        mock_content = MagicMock()
        mock_content.parts = [mock_part]

        mock_candidate = MagicMock()
        mock_candidate.content = mock_content
        mock_api_response.candidates = [mock_candidate]

        provider.gemini_model.generate_content.return_value = mock_api_response

        # Act
        result = provider._gemini_completion(messages, temperature, None, False)

        # Assert
        # 1. Check GenerationConfig call
        mock_genai_types.GenerationConfig.assert_called_once_with(temperature=temperature)

        # 2. Check generate_content call (using ANY for converted messages)
        provider.gemini_model.generate_content.assert_called_once_with(
            contents=ANY, # Check the converted structure if needed, but ANY is simpler
            generation_config=mock_config,
            # tools=None should not be passed if gemini_tools is None
        )
        # Verify 'tools' was not in kwargs if None
        call_args, call_kwargs = provider.gemini_model.generate_content.call_args
        assert 'tools' not in call_kwargs

        # 3. Check the returned output
        assert result == expected_output

    @patch('core.llm.genai_types')
    def test_gemini_completion_api_call_error(self, mock_genai_types, gemini_provider):
        # Arrange
        provider, _ = gemini_provider
        messages = [{"role": "user", "content": "Hello"}]
        temperature = 0.7
        test_error = google.api_core.exceptions.InternalServerError("Test API error")

        # Mock the GenerationConfig
        mock_config = MagicMock()
        mock_genai_types.GenerationConfig.return_value = mock_config

        # Configure generate_content to raise an error
        provider.gemini_model.generate_content.side_effect = test_error

        # Act & Assert
        with pytest.raises(google.api_core.exceptions.InternalServerError, match="Test API error") as excinfo:
            provider._gemini_completion(messages, temperature, None, False)

        # Check that the correct exception was raised
        assert excinfo.value is test_error

        # Check GenerationConfig call
        mock_genai_types.GenerationConfig.assert_called_once_with(temperature=temperature)

        # Check generate_content call
        provider.gemini_model.generate_content.assert_called_once_with(
            contents=ANY,
            generation_config=mock_config
        )
        # Verify 'tools' was not in kwargs if None
        call_args, call_kwargs = provider.gemini_model.generate_content.call_args
        assert 'tools' not in call_kwargs

    # TODO: Add test case for when API returns candidates but no text/function_call in parts
    # TODO: Add test case for when API returns no candidates