import pytest
from unittest.mock import patch, MagicMock

from core.coordinator import SwarmCoordinator


class TestSwarmCoordinator:
    @pytest.fixture
    def mock_config(self):
        return {
            "llm": {
                "openai": {
                    "api_key": "test_key",
                    "models": {"gpt-4o": {"temperature": 0.7}},
                }
            },
            "scan": {"max_urls": 10, "timeout": 30},
        }

    def test_initialization(self, mock_config):
        # Arrange & Act
        with (
            patch("core.coordinator.LLMProvider") as mock_llm,
            patch("core.coordinator.Scanner") as mock_scanner,
            patch("core.coordinator.Reporter") as mock_reporter,
        ):
            # Setup mocks
            mock_llm_instance = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_reporter_instance = MagicMock()

            mock_llm.return_value = mock_llm_instance
            mock_scanner.return_value = mock_scanner_instance
            mock_reporter.return_value = mock_reporter_instance

            # Create the coordinator
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="gemini",  # Changed provider
                scope="url",
                output_dir="/tmp/reports",
                config=mock_config,
                google_api_key="test_google_key",  # Added google key
            )

            # Assert
            assert coordinator.url == "https://example.com"
            assert coordinator.model == "gpt-4o"
            assert coordinator.provider == "gemini"  # Changed provider
            assert coordinator.scope == "url"
            assert coordinator.output_dir == "/tmp/reports"
            assert coordinator.config == mock_config
            assert coordinator.llm_provider == mock_llm_instance
            assert coordinator.scanner == mock_scanner_instance
            assert coordinator.reporter == mock_reporter_instance

            mock_llm.assert_called_once_with(
                provider="gemini",  # Changed provider
                model="gpt-4o",
                openai_api_key=None,
                anthropic_api_key=None,
                google_api_key="test_google_key",  # Added google key check
            )
            mock_scanner.assert_called_once()
            mock_reporter.assert_called_once_with("/tmp/reports")

    def test_initialization_no_google_key(self, mock_config):
        # Arrange & Act (Test case for when google_api_key is not provided)
        with (
            patch("core.coordinator.LLMProvider") as mock_llm,
            patch("core.coordinator.Scanner") as mock_scanner,
            patch("core.coordinator.Reporter") as mock_reporter,
        ):
            # Setup mocks
            mock_llm_instance = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_reporter_instance = MagicMock()

            mock_llm.return_value = mock_llm_instance
            mock_scanner.return_value = mock_scanner_instance
            mock_reporter.return_value = mock_reporter_instance

            # Create the coordinator without google_api_key
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",  # Using openai here, key should still be None
                scope="url",
                output_dir="/tmp/reports",
                config=mock_config,
                # google_api_key is omitted, should default to None
            )

            # Assert
            assert coordinator.provider == "openai"
            assert coordinator.llm_provider == mock_llm_instance

            # Verify LLMProvider called with google_api_key=None
            mock_llm.assert_called_once_with(
                provider="openai",
                model="gpt-4o",
                openai_api_key=None,
                anthropic_api_key=None,
                google_api_key=None,  # Assert it defaults to None
            )
            mock_scanner.assert_called_once()
            mock_reporter.assert_called_once_with("/tmp/reports")

    def test_run_simple_scope(self, mock_config):
        # Arrange
        with (
            patch("core.coordinator.LLMProvider") as mock_llm,
            patch("core.coordinator.Scanner") as mock_scanner,
            patch("core.coordinator.Reporter") as mock_reporter,
            patch("core.coordinator.create_agent_swarm") as mock_create_swarm,
        ):
            # Setup mocks
            mock_llm_instance = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_reporter_instance = MagicMock()
            mock_security_swarm = MagicMock()

            mock_llm.return_value = mock_llm_instance
            mock_scanner.return_value = mock_scanner_instance
            mock_reporter.return_value = mock_reporter_instance
            mock_create_swarm.return_value = mock_security_swarm

            # Mock page loading
            mock_page = MagicMock()
            mock_scanner_instance.load_page.return_value = mock_page
            mock_scanner_instance.extract_page_info.return_value = {
                "url": "https://example.com",
                "title": "Example",
            }

            # Mock security testing
            mock_security_swarm.run.return_value = [
                {"type": "XSS", "url": "https://example.com", "severity": "high"}
            ]

            # Mock report generation
            mock_reporter_instance.generate_report.return_value = (
                "/tmp/reports/report.md"
            )

            # Create the coordinator
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",
                scope="url",
                output_dir="/tmp/reports",
                config=mock_config,
            )

            # Act
            result = coordinator.run()

            # Assert
            assert result["urls_discovered"] == 1
            assert result["urls_scanned"] == 1
            assert result["vulnerabilities_found"] == 1
            assert result["report_path"] == "/tmp/reports/report.md"

            # Verify method calls
            mock_scanner_instance.start.assert_called_once()
            mock_scanner_instance.load_page.assert_called_once_with(
                "https://example.com"
            )
            mock_scanner_instance.extract_page_info.assert_called_once_with(mock_page)
            mock_create_swarm.assert_called_once_with(
                agent_type="security",
                llm_provider=mock_llm_instance,
                scanner=mock_scanner_instance,
                config=mock_config,
            )
            mock_security_swarm.run.assert_called_once_with(
                "https://example.com",
                mock_page,
                {"url": "https://example.com", "title": "Example"},
            )
            mock_reporter_instance.generate_report.assert_called_once()
            mock_scanner_instance.stop.assert_called_once()

    def test_run_expanded_scope(self, mock_config):
        # Arrange
        with (
            patch("core.coordinator.LLMProvider") as mock_llm,
            patch("core.coordinator.Scanner") as mock_scanner,
            patch("core.coordinator.Reporter") as mock_reporter,
            patch("core.coordinator.create_agent_swarm") as mock_create_swarm,
        ):
            # Setup mocks
            mock_llm_instance = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_reporter_instance = MagicMock()
            mock_discovery_swarm = MagicMock()
            mock_security_swarm = MagicMock()

            mock_llm.return_value = mock_llm_instance
            mock_scanner.return_value = mock_scanner_instance
            mock_reporter.return_value = mock_reporter_instance

            # Mock create_agent_swarm to return different agents based on type
            def mock_create_agent(agent_type, **kwargs):
                if agent_type == "discovery":
                    return mock_discovery_swarm
                else:
                    return mock_security_swarm

            mock_create_swarm.side_effect = mock_create_agent

            # Mock discovery
            additional_urls = ["https://example.com/page1", "https://example.com/page2"]
            mock_discovery_swarm.discover_urls.return_value = additional_urls

            # Mock page loading
            mock_page = MagicMock()
            mock_scanner_instance.load_page.return_value = mock_page
            mock_scanner_instance.extract_page_info.return_value = {
                "url": "https://example.com",
                "title": "Example",
            }

            # Mock security testing
            mock_security_swarm.run.return_value = [
                {"type": "XSS", "url": "https://example.com", "severity": "high"}
            ]

            # Mock report generation
            mock_reporter_instance.generate_report.return_value = (
                "/tmp/reports/report.md"
            )

            # Create the coordinator
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",
                scope="domain",  # Expanded scope
                output_dir="/tmp/reports",
                config=mock_config,
            )

            # Act
            result = coordinator.run()

            # Assert
            assert result["urls_discovered"] == 3  # Base URL + 2 discovered
            assert result["urls_scanned"] == 3
            assert result["vulnerabilities_found"] == 3  # One vuln per URL

            # Verify discovery agent was created and used
            mock_create_swarm.assert_any_call(
                agent_type="discovery",
                llm_provider=mock_llm_instance,
                scanner=mock_scanner_instance,
                config=mock_config,
            )
            mock_discovery_swarm.discover_urls.assert_called_once_with(
                base_url="https://example.com", scope="domain", subdomains=False
            )

            # Verify each URL was processed
            assert mock_scanner_instance.load_page.call_count == 3
            assert mock_security_swarm.run.call_count == 3

    def test_load_page_failure(self, mock_config):
        # Arrange
        with (
            patch("core.coordinator.LLMProvider") as mock_llm,
            patch("core.coordinator.Scanner") as mock_scanner,
            patch("core.coordinator.Reporter") as mock_reporter,
            patch("core.coordinator.create_agent_swarm") as mock_create_swarm,
        ):
            # Setup mocks
            mock_llm_instance = MagicMock()
            mock_scanner_instance = MagicMock()
            mock_reporter_instance = MagicMock()

            mock_llm.return_value = mock_llm_instance
            mock_scanner.return_value = mock_scanner_instance
            mock_reporter.return_value = mock_reporter_instance

            # Mock page loading failure
            mock_scanner_instance.load_page.return_value = None

            # Mock report generation
            mock_reporter_instance.generate_report.return_value = (
                "/tmp/reports/report.md"
            )

            # Create the coordinator
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",
                scope="url",
                output_dir="/tmp/reports",
                config=mock_config,
            )

            # Act
            result = coordinator.run()

            # Assert
            assert result["urls_discovered"] == 1
            assert result["urls_scanned"] == 1
            assert (
                result["vulnerabilities_found"] == 0
            )  # No vulnerabilities found due to page load failure

            # Verify method calls
            mock_scanner_instance.start.assert_called_once()
            mock_scanner_instance.load_page.assert_called_once_with(
                "https://example.com"
            )
            mock_scanner_instance.extract_page_info.assert_not_called()
            mock_create_swarm.assert_not_called()
            mock_reporter_instance.generate_report.assert_called_once_with([])
            mock_scanner_instance.stop.assert_called_once()
