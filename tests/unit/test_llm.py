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
        tool_call_dict = {
            "id": "call_123",
            "type": "function",
            "function": {
                "name": "test_function", 
                "arguments": '{"arg1": "value1"}'
            }
        }
        
        # Create a custom MagicMock with specific return values for the tool calls
        def create_tool_call_response(mock_response):
            # Create a new instance of the response
            response = MagicMock()
            response.choices = [MagicMock()]
            response.choices[0].message = MagicMock()
            response.choices[0].message.content = None
            response.choices[0].finish_reason = "tool_calls"
            response.model = "gpt-4o"
            
            # Set up tool calls in a way that works with our implementation
            response.choices[0].message.tool_calls = [tool_call_dict]
            return response
        
        mock_client.chat.completions.create.return_value = create_tool_call_response(mock_openai_response)
        
        provider = LLMProvider(provider="openai", model="gpt-4o")
        
        messages = [{"role": "user", "content": "Hello"}]
        tools = [{"type": "function", "function": {"name": "test_function", "parameters": {}}}]
        
        # Act
        result = provider.chat_completion(messages, tools=tools)
        
        tool_calls = result.choices[0].message.tool_calls
        first_call = tool_calls[0]
        first_id = first_call.get("id") if isinstance(first_call, dict) else first_call.id
        first_function = first_call.get("function") if isinstance(first_call, dict) else first_call.function
        first_name = first_function.get("name") if isinstance(first_function, dict) else first_function.name

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
            model="text-embedding-3-small",
            input="Test text"
        )
