# tests/unit/test_llm.py
import os
import pytest
import json # <-- Added import
from unittest.mock import patch, MagicMock, call # <-- Added import

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

            # Assert - Check the *last* debug call which logs the final structure
            # The log uses an f-string, so there's only one argument in logged_args
            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0] # Get the single argument from the call

            # Extract the JSON part from the logged message
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

            # Re-parse the logged JSON to compare structures
            logged_gemini_messages = json.loads(logged_data_str)

            assert logged_gemini_messages == expected_gemini_messages
            # Removed duplicate assertion
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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

            # Parse with default=str if needed, though mocks should be handled by string check below
            logged_gemini_messages = json.loads(logged_data_str) # Mocks won't be in the parsed dict

            assert len(logged_gemini_messages) == 2
            assert logged_gemini_messages[0]['role'] == 'user'
            assert logged_gemini_messages[1]['role'] == 'model'
            # Check the parts structure within the model message
            # Direct comparison is hard due to mock, check types and count
            model_parts = logged_gemini_messages[1]['parts']
            assert len(model_parts) == 2
            assert isinstance(model_parts[0], dict) and 'text' in model_parts[0]
            # The mock part will be stringified by json.dumps(default=str)
            # We can't reliably assert the mock object string representation here after json.loads
            # Instead, rely on the genai_types.Part call assertion below

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

            # Parse with default=str if needed, though mocks should be handled by string check below
            logged_gemini_messages = json.loads(logged_data_str) # Mocks won't be in the parsed dict

            # Expected structure: user, model (func call), user (func response)
            assert len(logged_gemini_messages) == 3
            assert logged_gemini_messages[0]['role'] == 'user'
            assert logged_gemini_messages[1]['role'] == 'model'
            assert logged_gemini_messages[2]['role'] == 'user' # Tool result becomes user role
            # Check parts structure - again, direct mock comparison after json.loads is unreliable
            # Rely on call assertions below

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

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

            assert mock_logger_debug.call_count > 0, "Logger debug was not called"
            final_log_call = mock_logger_debug.call_args_list[-1]
            logged_message_full = final_log_call[0][0]
            json_prefix = "Final Gemini messages structure:\n"
            assert logged_message_full.startswith(json_prefix), f"Log message mismatch: {logged_message_full}"
            logged_data_str = logged_message_full[len(json_prefix):]

            # Parse with default=str if needed, though mocks should be handled by string check below
            logged_gemini_messages = json.loads(logged_data_str) # Mocks won't be in the parsed dict

            assert len(logged_gemini_messages) == 2
            assert logged_gemini_messages[0]['role'] == 'user'
            assert logged_gemini_messages[0]['parts'][0]['text'] == "System instruction."
            assert logged_gemini_messages[1]['role'] == 'user'
            # Check parts structure - again, direct mock comparison after json.loads is unreliable
            # Rely on call assertions below

            mock_genai_types.FunctionResponse.assert_called_once_with(name=tool_name, response=expected_response_data)
            mock_genai_types.Part.assert_called_once_with(function_response=mock_genai_types.FunctionResponse.return_value)