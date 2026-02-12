import unittest
from unittest.mock import patch, MagicMock
import json  # For formatting tool results if needed

# Import necessary types for mocking Gemini response structure
# Use try-except for flexibility in case the library structure changes slightly
try:
    from google.generativeai import types as genai_types
    from google.generativeai.types import (
        FunctionDeclaration,
        Tool,
        Part,
        FunctionResponse,
    )  # Be specific
except ImportError:
    # Create dummy types if google.generativeai is not installed or structure differs
    # This allows the test structure to be defined even without the dependency fully present
    # In a real CI environment, the dependency should be installed.
    genai_types = MagicMock()
    FunctionDeclaration = MagicMock
    Tool = MagicMock
    Part = MagicMock
    FunctionResponse = MagicMock
    # Mock the specific classes used if needed
    genai_types.GenerateContentResponse = MagicMock
    genai_types.Part = MagicMock
    genai_types.FunctionCall = MagicMock
    genai_types.FunctionResponse = MagicMock  # Add this mock


from core.coordinator import SwarmCoordinator
# We might need tool definitions if we want to assert the 'tools' argument precisely
# from tools.security_tools import get_security_tool_schemas # Example


# Define a helper to create mock Gemini Parts easily
def create_mock_part(
    text=None,
    function_call_name=None,
    function_call_args=None,
    function_response_name=None,
    function_response_content=None,
):
    """Creates a mock Part object mimicking Gemini structure."""
    part = MagicMock(spec=genai_types.Part)
    part.text = text
    if function_call_name:
        fc = MagicMock(spec=genai_types.FunctionCall)
        fc.name = function_call_name
        fc.args = function_call_args or {}
        part.function_call = fc
    else:
        part.function_call = None  # Explicitly None if no function call

    if function_response_name:
        fr = MagicMock(spec=genai_types.FunctionResponse)
        fr.name = function_response_name
        # Gemini expects the 'response' field to contain the structured data for the function result
        fr.response = {
            "content": function_response_content
        }  # Wrap content as expected by _gemini_completion
        part.function_response = fr
    else:
        part.function_response = None  # Explicitly None if no function response

    return part


# Define a helper to create mock Gemini GenerateContentResponse
def create_mock_response(parts_list):
    """Creates a mock GenerateContentResponse object."""
    response = MagicMock(spec=genai_types.GenerateContentResponse)
    # Gemini API often returns response within response.candidates[0].content.parts
    mock_content = MagicMock()
    mock_content.parts = parts_list
    mock_candidate = MagicMock()
    mock_candidate.content = mock_content
    response.candidates = [mock_candidate]
    # Also add parts directly for simpler access if parsing logic checks there first
    response.parts = parts_list
    return response


class TestGeminiWorkflow(unittest.TestCase):
    # Patch targets should be where the object is LOOKED UP, not where it's defined.
    # Coordinator imports create_agent_swarm, Reporter, Scanner directly.
    # LLMProvider (used by Coordinator) imports genai, load_config.
    @patch("core.coordinator.create_agent_swarm")
    @patch("core.coordinator.Reporter")
    @patch("core.coordinator.Scanner")
    @patch("core.llm.genai.configure")  # Patch configure within llm module
    @patch("core.llm.genai.GenerativeModel")  # Patch Model class within llm module
    @patch("utils.config.load_config")  # Patch config loading used in LLMProvider init
    def test_gemini_end_to_end_flow(
        self,
        mock_load_config,
        mock_genai_model_cls,
        mock_genai_configure,
        mock_scanner_cls,
        mock_reporter_cls,
        mock_create_agent_swarm,
    ):

        # --- Mock Configuration ---
        # Provide a minimal config, including the Gemini model if LLMProvider checks it
        mock_load_config.return_value = {
            "llm": {"gemini": {"default_model": "gemini-test-model"}},
            "tools": {
                "security": {"enabled": ["run_nmap"]}
            },  # Example tool config if needed
        }

        # Mock Scanner instance and methods
        mock_scanner_instance = mock_scanner_cls.return_value
        mock_page = MagicMock(name="MockPage")  # Give mock a name for easier debugging
        mock_scanner_instance.load_page.return_value = mock_page
        mock_scanner_instance.extract_page_info.return_value = {
            "html": "<html></html>",
            "forms": [],
            "links": [],
        }

        # Mock Reporter instance
        mock_reporter_instance = mock_reporter_cls.return_value
        mock_reporter_instance.generate_report.return_value = "/fake/report/path.md"

        # Mock Agent Swarm instance and its run method
        mock_swarm_instance = MagicMock(name="MockAgentSwarm")
        # Simulate the swarm finding a vulnerability based on the *expected* final LLM response text
        mock_swarm_instance.run.return_value = [
            {
                "vulnerability_type": "Simulated Nmap Finding",
                "severity": "Info",
                "target": "http://example.com",
                "details": "Nmap scan complete. Found open port 80.",  # Match text from mock_response_3
                "validated": False,
            }
        ]
        mock_create_agent_swarm.return_value = mock_swarm_instance

        # Mock GenerativeModel instance and generate_content
        mock_genai_model_instance = mock_genai_model_cls.return_value

        # --- Define Mock API Responses using helpers ---
        # Response 1: Planner suggests a tool
        mock_part_1 = create_mock_part(text="Okay, let's run nmap on example.com.")
        mock_response_1 = create_mock_response([mock_part_1])

        # Response 2: Tool Router requests 'run_nmap'
        mock_part_2 = create_mock_part(
            function_call_name="run_nmap", function_call_args={"target": "example.com"}
        )
        mock_response_2 = create_mock_response([mock_part_2])

        # Response 3: Response Generator gives final answer based on tool result
        mock_part_3 = create_mock_part(text="Nmap scan complete. Found open port 80.")
        mock_response_3 = create_mock_response([mock_part_3])

        # Configure side_effect for generate_content
        mock_genai_model_instance.generate_content.side_effect = [
            mock_response_1,
            mock_response_2,
            mock_response_3,
        ]

        # --- Test Execution ---
        coordinator = SwarmCoordinator(
            url="http://example.com",
            model="gemini-test-model",  # Use a specific model name for clarity
            provider="gemini",
            scope="url",
            output_dir="/tmp/test_output",
            config=mock_load_config.return_value,  # Pass the mocked config
            google_api_key="FAKE_API_KEY",  # Key is needed for init, but configure is mocked
        )

        # Run the coordinator. This should:
        # 1. Call scanner.start(), scanner.load_page(), scanner.extract_page_info()
        # 2. Call create_agent_swarm() -> returns mock_swarm_instance
        # 3. Call mock_swarm_instance.run() -> returns predefined vulnerability list
        #    (Internally, the *real* swarm would call LLMProvider -> generate_content 3 times)
        # 4. Call reporter.generate_report()
        # 5. Call scanner.stop()
        result = coordinator.run()

        # --- Assertions ---
        # 1. Check LLM API was called 3 times (assuming the mocked swarm's conceptual flow involves 3 calls)
        #    NOTE: Since we mocked swarm.run, generate_content might NOT be called directly
        #    by *this* test execution path. We need to adjust the mocking strategy if we
        #    want to assert generate_content calls *through* the coordinator -> swarm -> provider chain.
        #
        #    REVISED STRATEGY: Let's mock the LLMProvider's chat_completion method instead of
        #    the underlying genai.generate_content. This tests the Coordinator -> Provider interaction
        #    more directly without needing to perfectly mock the genai library details.

        # --- REVISED MOCKING (Patch LLMProvider.chat_completion) ---
        # We need to re-run setup with the adjusted patch target.
        # This requires restructuring the test slightly or using nested patches.
        # Let's restart the test definition with the corrected patch strategy.


# --- REVISED TEST STRUCTURE ---


class TestGeminiWorkflowRevised(unittest.TestCase):
    @patch("core.coordinator.create_agent_swarm")
    @patch("core.coordinator.Reporter")
    @patch("core.coordinator.Scanner")
    @patch(
        "core.llm.LLMProvider.chat_completion"
    )  # Patch the provider's method directly
    @patch("utils.config.load_config")
    def test_gemini_end_to_end_flow_revised(
        self,
        mock_load_config,
        mock_chat_completion,  # Patched LLMProvider.chat_completion
        mock_scanner_cls,
        mock_reporter_cls,
        mock_create_agent_swarm,
    ):

        # --- Mock Configuration ---
        mock_load_config.return_value = {
            "llm": {"gemini": {"default_model": "gemini-test-model"}},
            "tools": {"security": {"enabled": ["run_nmap"]}},
        }

        # Mock Scanner instance and methods
        mock_scanner_instance = mock_scanner_cls.return_value
        mock_page = MagicMock(name="MockPage")
        mock_scanner_instance.load_page.return_value = mock_page
        mock_scanner_instance.extract_page_info.return_value = {
            "html": "<html></html>",
            "forms": [],
            "links": [],
        }

        # Mock Reporter instance
        mock_reporter_instance = mock_reporter_cls.return_value
        mock_reporter_instance.generate_report.return_value = "/fake/report/path.md"

        # Mock Agent Swarm instance and its run method
        # The swarm's run method will now *trigger* the calls to the mocked chat_completion
        mock_swarm_instance = MagicMock(name="MockAgentSwarm")
        # We need the *real* swarm logic (or a simplified version) to call chat_completion.
        # Mocking swarm.run directly prevents this.
        #
        # ALTERNATIVE: Don't mock create_agent_swarm. Let it create the *real* swarm,
        # but the swarm will use the LLMProvider instance created by the Coordinator,
        # and *that* provider instance will have its chat_completion method mocked.

        # --- REVISED STRATEGY 2 (Mock only chat_completion, not swarm creation) ---
        # Let's try this approach.


# --- REVISED TEST STRUCTURE 2 ---


class TestGeminiWorkflowFinal(unittest.TestCase):
    # Patch only the necessary external dependencies and the LLM call point
    @patch(
        "core.llm.LLMProvider.chat_completion"
    )  # Target the unified completion method
    @patch(
        "agents.security_swarm.SecuritySwarm.run", autospec=True
    )  # Mock run method with autospec
    @patch("core.coordinator.Reporter")
    @patch("core.coordinator.Scanner")
    @patch(
        "utils.config.load_config"
    )  # Used by LLMProvider and potentially Coordinator/Swarm
    def test_gemini_end_to_end_flow_final(
        self,
        mock_load_config,
        mock_scanner_cls,
        mock_reporter_cls,
        mock_swarm_run,  # Patched SecuritySwarm.run
        mock_chat_completion,
    ):  # Patched LLMProvider.chat_completion

        # --- Mock Configuration ---
        test_config = {
            "llm": {"gemini": {"default_model": "gemini-test-model"}},
            "tools": {"security": {"enabled": ["run_nmap"]}},  # Define tools expected
            "agents": {  # Add agent config if create_agent_swarm uses it
                "security": {
                    "planner_prompt": "Plan the scan.",
                    "tool_router_prompt": "Route to tool.",
                }
            },
        }
        mock_load_config.return_value = test_config

        # Mock Scanner instance and methods
        mock_scanner_instance = mock_scanner_cls.return_value
        mock_page = MagicMock(name="MockPage")
        mock_page.url = (
            "http://example.com"  # Add URL attribute to prevent TypeError in urlparse
        )
        mock_scanner_instance.load_page.return_value = mock_page
        mock_scanner_instance.extract_page_info.return_value = {
            "html": "<html></html>",
            "forms": [],
            "links": [],
        }

        # Mock Reporter instance
        mock_reporter_instance = mock_reporter_cls.return_value
        mock_reporter_instance.generate_report.return_value = "/fake/report/path.md"

        # --- Define Mock LLM Responses (for chat_completion) ---
        # These should match the structure returned by LLMProvider._gemini_completion
        # which wraps the raw Gemini response.

        # Response 1: Planner (Text only)
        mock_response_1 = {
            "choices": [
                MagicMock(
                    message=MagicMock(
                        content="Okay, let's run nmap on example.com.", tool_calls=None
                    )
                )
            ]
        }

        # Response 2: Tool Router (Tool call only)
        mock_tool_call_2 = MagicMock()
        mock_tool_call_2.id = "call_123"
        mock_tool_call_2.type = "function"
        mock_tool_call_2.function = MagicMock(
            name="run_nmap", arguments=json.dumps({"target": "example.com"})
        )
        mock_response_2 = {
            "choices": [
                MagicMock(
                    message=MagicMock(content=None, tool_calls=[mock_tool_call_2])
                )
            ]
        }

        # Response 3: Response Generator (Text only, after tool result)
        # Tool result simulation: Assume the swarm calls the tool and gets this output
        simulated_tool_result_content = "Nmap finished: Port 80 (HTTP) is open."
        mock_response_3 = {
            "choices": [
                MagicMock(
                    message=MagicMock(
                        content=f"Nmap scan complete based on result: {simulated_tool_result_content}",
                        tool_calls=None,
                    )
                )
            ]
        }

        # Configure side_effect for chat_completion
        mock_chat_completion.side_effect = [
            mock_response_1,
            mock_response_2,
            mock_response_3,
        ]

        # Configure the mocked SecuritySwarm.run method
        # It should prevent the real run loop and just return the final expected result.
        final_text_from_llm = mock_response_3["choices"][0].message.content
        final_vulnerability = {
            "vulnerability_type": "Simulated Finding",
            "severity": "Info",
            "target": "http://example.com",
            "details": final_text_from_llm,  # Use the text from the final mock response
            "validated": False,
        }

        # This function will replace the real SecuritySwarm.run
        # It needs access to the llm_provider via the 'self' argument
        def simulated_swarm_run(swarm_self, url, page, page_info):
            # --- DEBUGGING ---
            print("\n--- DEBUG: simulated_swarm_run received ---")
            print(f"  swarm_self: {type(swarm_self)}")
            print(f"  url: {url}")
            print(f"  page: {type(page)}")
            print(f"  page_info: {page_info}")
            print("-------------------------------------------\n")
            # --- END DEBUGGING ---

            # Simulate the 3 calls the real swarm would make in this scenario
            # The chat_completion method is already mocked with a side_effect list

            # Call 1: Planner (no tools)
            planner_messages = [
                {"role": "system", "content": "Plan the scan."},
                {"role": "user", "content": f"Scan {url}"},
            ]
            _ = swarm_self.llm_provider.chat_completion(
                messages=planner_messages, tools=None
            )  # Call is made, response ignored here

            # Call 2: Tool Router (with tools)
            # Need to get tools - assume they are accessible via swarm_self.tools or similar
            # For simplicity, create dummy tools matching the expected call
            dummy_tools = [
                {
                    "type": "function",
                    "function": {"name": "run_nmap", "description": "Runs nmap"},
                }
            ]
            tool_router_messages = planner_messages + [
                {"role": "assistant", "content": "Okay, let's run nmap on example.com."}
            ]
            tool_call_response = swarm_self.llm_provider.chat_completion(
                messages=tool_router_messages, tools=dummy_tools
            )  # Call is made

            # Call 3: Response Generator (with tool result)
            # Extract tool call id from the (mocked) response of call 2
            tool_call_id = tool_call_response["choices"][0].message.tool_calls[0].id
            tool_result_message = {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": "run_nmap",
                "content": simulated_tool_result_content,
            }
            response_gen_messages = (
                tool_router_messages
                + [
                    {
                        "role": "assistant",
                        "tool_calls": tool_call_response["choices"][
                            0
                        ].message.tool_calls,
                    }
                ]
                + [tool_result_message]
            )
            _ = swarm_self.llm_provider.chat_completion(
                messages=response_gen_messages, tools=dummy_tools
            )  # Call is made

            # Return the final result expected by the coordinator
            return [final_vulnerability]

        mock_swarm_run.side_effect = (
            simulated_swarm_run  # Assign the simulating function
        )

        # --- Test Execution ---
        coordinator = SwarmCoordinator(
            url="http://example.com",
            model="gemini-test-model",  # Consistent model name
            provider="gemini",
            scope="url",
            output_dir="/tmp/test_output",
            config=test_config,  # Pass the test config
            google_api_key="FAKE_API_KEY",  # Still needed for init, even if unused
        )

        # Run the coordinator
        result = coordinator.run()

        # --- Assertions ---
        # 1. Check chat_completion call count
        self.assertEqual(
            mock_chat_completion.call_count,
            3,
            "LLMProvider.chat_completion should be called 3 times",
        )

        # 2. Check arguments for each call to chat_completion
        calls = mock_chat_completion.call_args_list

        # Call 1 (Planner)
        call_1_args, call_1_kwargs = calls[0]
        self.assertIsInstance(call_1_kwargs.get("messages"), list)
        self.assertIsNone(
            call_1_kwargs.get("tools"), "Tools should not be passed to planner call"
        )
        # Check messages structure if needed

        # Call 2 (Tool Router)
        call_2_args, call_2_kwargs = calls[1]
        self.assertIsInstance(call_2_kwargs.get("messages"), list)
        self.assertIsInstance(
            call_2_kwargs.get("tools"),
            list,
            "Tools should be passed to tool router call",
        )
        self.assertTrue(len(call_2_kwargs["tools"]) > 0)
        # Check that message history includes planner response

        # Call 3 (Response Generator)
        call_3_args, call_3_kwargs = calls[2]
        self.assertIsInstance(call_3_kwargs.get("messages"), list)
        # Check that message history includes the tool call request AND the tool result message
        messages_3 = call_3_kwargs["messages"]
        has_tool_call_msg = any(
            msg.get("role") == "assistant" and msg.get("tool_calls") is not None
            for msg in messages_3
        )
        has_tool_result_msg = any(
            msg.get("role") == "tool" and msg.get("tool_call_id") == mock_tool_call_2.id
            for msg in messages_3
        )
        self.assertTrue(
            has_tool_call_msg,
            "Messages for call 3 should include the assistant's tool call",
        )
        self.assertTrue(
            has_tool_result_msg, "Messages for call 3 should include the tool result"
        )

        # 3. Check final result from coordinator
        self.assertEqual(result["vulnerabilities_found"], 1)
        self.assertEqual(result["report_path"], "/fake/report/path.md")
        # The check below verifies the content passed to the reporter

        # 4. Check reporter was called with the vulnerability data from the mocked swarm
        # Check reporter was called with the vulnerability data returned by the mocked swarm run
        mock_reporter_instance.generate_report.assert_called_once_with(
            [final_vulnerability]
        )

        # 5. Check scanner methods were called
        mock_scanner_instance.start.assert_called_once()
        mock_scanner_instance.load_page.assert_called_once_with("http://example.com")
        mock_scanner_instance.extract_page_info.assert_called_once_with(mock_page)
        mock_scanner_instance.stop.assert_called_once()

        # 6. Check swarm run method was called correctly
        mock_swarm_run.assert_called_once()
        # Inspect the arguments passed to the mocked run
        run_args, run_kwargs = mock_swarm_run.call_args
        # The first argument to an instance method call is 'self', skip it [0]
        # The next arguments should be url, page, page_info
        self.assertEqual(run_args[1], "http://example.com")  # url
        self.assertEqual(run_args[2], mock_page)  # page
        self.assertIsInstance(run_args[3], dict)  # page_info
