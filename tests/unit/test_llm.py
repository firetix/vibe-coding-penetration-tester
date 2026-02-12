import os
import pytest
from unittest.mock import patch, MagicMock

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

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_openai_codex_model_initialization(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Act
        provider = LLMProvider(provider="openai", model="codex-5.3")

        # Assert
        assert provider.provider == "openai"
        assert provider.model == "codex-5.3"
        assert provider.client == mock_client
        mock_openai.assert_called_once_with(api_key="test_key")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_openai_o_series_model_initialization(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Act
        provider = LLMProvider(provider="openai", model="o3")

        # Assert
        assert provider.provider == "openai"
        assert provider.model == "o3"
        assert provider.client == mock_client
        mock_openai.assert_called_once_with(api_key="test_key")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")
    def test_openai_unknown_model_falls_back_to_default(self, mock_openai):
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client

        # Act
        provider = LLMProvider(provider="openai", model="random-model-name")

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

        mock_client.chat.completions.create.return_value = create_tool_call_response(
            mock_openai_response
        )

        provider = LLMProvider(provider="openai", model="gpt-4o")

        messages = [{"role": "user", "content": "Hello"}]
        tools = [
            {
                "type": "function",
                "function": {"name": "test_function", "parameters": {}},
            }
        ]

        # Act
        result = provider.chat_completion(messages, tools=tools)
        tool_calls = result.choices[0].message.tool_calls
        first_call = tool_calls[0]
        first_id = (
            first_call.get("id") if isinstance(first_call, dict) else first_call.id
        )
        first_function = (
            first_call.get("function")
            if isinstance(first_call, dict)
            else first_call.function
        )
        first_name = (
            first_function.get("name")
            if isinstance(first_function, dict)
            else first_function.name
        )

        # Assert
        assert result.choices[0].message.content is None
        assert tool_calls is not None
        assert isinstance(tool_calls, list)
        assert len(tool_calls) > 0
        assert first_id == "call_123"
        assert first_name == "test_function"
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
            model="text-embedding-3-small", input="Test text"
        )

    # --- Gemini Tests ---

    @patch("core.llm.genai")
    @patch("core.llm.os.getenv", return_value=None)  # Ensure env var is not used
    def test_gemini_initialization_with_key(self, mock_getenv, mock_genai):
        # Arrange
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        test_api_key = "explicit_gemini_key"
        expected_model_name = "gemini-2.0-flash"

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

    @patch("core.llm.genai")
    @patch.dict(os.environ, {"GOOGLE_API_KEY": "test_env_key"})
    def test_gemini_initialization_with_env_var(self, mock_genai):
        # Arrange
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        expected_model_name = "gemini-2.0-flash"

        # Act
        provider = LLMProvider(provider="gemini")  # No explicit key

        # Assert
        assert provider.provider == "gemini"
        assert provider.google_api_key == "test_env_key"
        assert provider.model == expected_model_name
        assert provider.gemini_model == mock_model
        mock_genai.configure.assert_called_once_with(api_key="test_env_key")
        mock_genai.GenerativeModel.assert_called_once_with(expected_model_name)

    @patch("core.llm.genai")
    @patch("core.llm.os.getenv", return_value=None)  # Mock getenv to return None
    def test_gemini_initialization_no_key(self, mock_getenv, mock_genai):
        # Arrange (No key provided explicitly or via env)

        # Act & Assert
        with pytest.raises(ValueError, match="Google API Key not found"):
            LLMProvider(provider="gemini")

        mock_genai.configure.assert_not_called()
        mock_genai.GenerativeModel.assert_not_called()
        # Check that getenv was called for GOOGLE_API_KEY among others
        from unittest.mock import call

        assert call("GOOGLE_API_KEY") in mock_getenv.call_args_list

    @patch("core.llm.genai")
    @patch.dict(os.environ, {"GOOGLE_API_KEY": "test_key"})  # Need key for init
    @patch("core.llm.LLMProvider._gemini_completion")  # Patch the target method
    def test_gemini_chat_completion_routes(self, mock_gemini_completion, mock_genai):
        # Arrange
        # Mock genai configure and model init to avoid errors during LLMProvider instantiation
        mock_model_instance = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model_instance

        provider = LLMProvider(provider="gemini")
        # Define return value for the mocked method to match expected structure
        mock_gemini_completion.return_value = {
            "content": "mocked gemini response",
            "tool_calls": [],
        }

        messages = [{"role": "user", "content": "Hello Gemini"}]
        temperature = 0.5
        tools = None
        json_mode = False

        # Act
        result = provider.chat_completion(messages, temperature, tools, json_mode)

        # Assert
        mock_gemini_completion.assert_called_once_with(
            messages, temperature, tools, json_mode
        )
        # Check the structure returned by the mocked method
        assert result["content"] == "mocked gemini response"
        assert result["tool_calls"] == []
        # Ensure genai was configured during init
        mock_genai.configure.assert_called_once_with(api_key="test_key")
        mock_genai.GenerativeModel.assert_called_once()
