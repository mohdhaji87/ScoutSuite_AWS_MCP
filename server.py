import asyncio
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server
import subprocess
from typing import Optional

app = Server("scoutsuite-aws-server")

def tool_schema(properties, required=None, description=None):
    schema = {
        "type": "object",
        "properties": properties,
        "required": required or []
    }
    if description:
        schema["description"] = description
    return schema

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="run_scoutsuite_aws_basic",
            description="Run a basic ScoutSuite scan on AWS using default credentials.",
            inputSchema=tool_schema({}, [])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_profile",
            description="Run ScoutSuite scan on AWS using a specific AWS CLI profile.",
            inputSchema=tool_schema({
                "profile": {"type": "string", "description": "AWS CLI profile name"}
            }, ["profile"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_report_dir",
            description="Run ScoutSuite scan on AWS and save the report to a custom directory.",
            inputSchema=tool_schema({
                "report_dir": {"type": "string", "description": "Directory to save the ScoutSuite report"}
            }, ["report_dir"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_ruleset",
            description="Run ScoutSuite scan on AWS using a custom ruleset.",
            inputSchema=tool_schema({
                "ruleset": {"type": "string", "description": "Path to custom ruleset JSON file"}
            }, ["ruleset"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_exceptions",
            description="Run ScoutSuite scan on AWS using an exceptions file.",
            inputSchema=tool_schema({
                "exceptions_file": {"type": "string", "description": "Path to exceptions JSON file"}
            }, ["exceptions_file"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_access_keys",
            description="Run ScoutSuite scan on AWS using direct access keys.",
            inputSchema=tool_schema({
                "access_key_id": {"type": "string", "description": "AWS Access Key ID"},
                "secret_access_key": {"type": "string", "description": "AWS Secret Access Key"},
                "session_token": {"type": "string", "description": "AWS Session Token (optional)"}
            }, ["access_key_id", "secret_access_key"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_with_logging",
            description="Run ScoutSuite scan on AWS with a specific logging level.",
            inputSchema=tool_schema({
                "log_level": {"type": "string", "description": "Logging level (DEBUG, INFO, WARNING, ERROR)"}
            }, ["log_level"])
        ),
        types.Tool(
            name="run_scoutsuite_aws_flexible",
            description="Run ScoutSuite scan on AWS with any combination of options.",
            inputSchema=tool_schema({
                "profile": {"type": "string", "description": "AWS CLI profile name (optional)"},
                "report_dir": {"type": "string", "description": "Directory to save the ScoutSuite report (optional)"},
                "ruleset": {"type": "string", "description": "Path to custom ruleset JSON file (optional)"},
                "exceptions_file": {"type": "string", "description": "Path to exceptions JSON file (optional)"},
                "access_key_id": {"type": "string", "description": "AWS Access Key ID (optional)"},
                "secret_access_key": {"type": "string", "description": "AWS Secret Access Key (optional)"},
                "session_token": {"type": "string", "description": "AWS Session Token (optional)"},
                "log_level": {"type": "string", "description": "Logging level (optional)"}
            })
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    def run_scoutsuite(cmd, env=None):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
            output = proc.stdout + "\n" + proc.stderr
            return [types.TextContent(type="text", text=output)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error running ScoutSuite: {e}")]

    if name == "run_scoutsuite_aws_basic":
        cmd = ["scout", "aws", "--no-browser"]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_profile":
        profile = arguments["profile"]
        cmd = ["scout", "aws", "--no-browser", "--profile", profile]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_report_dir":
        report_dir = arguments["report_dir"]
        cmd = ["scout", "aws", "--no-browser", "--report-dir", report_dir]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_ruleset":
        ruleset = arguments["ruleset"]
        cmd = ["scout", "aws", "--no-browser", "--ruleset", ruleset]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_exceptions":
        exceptions_file = arguments["exceptions_file"]
        cmd = ["scout", "aws", "--no-browser", "--exceptions-file", exceptions_file]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_access_keys":
        access_key_id = arguments["access_key_id"]
        secret_access_key = arguments["secret_access_key"]
        session_token = arguments.get("session_token")
        cmd = ["scout", "aws", "--no-browser", "--access-keys", "--access-key-id", access_key_id, "--secret-access-key", secret_access_key]
        if session_token:
            cmd += ["--session-token", session_token]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_with_logging":
        log_level = arguments["log_level"]
        cmd = ["scout", "aws", "--no-browser", "--log-level", log_level]
        return run_scoutsuite(cmd)

    if name == "run_scoutsuite_aws_flexible":
        cmd = ["scout", "aws", "--no-browser"]
        env = None
        if arguments.get("profile"):
            cmd += ["--profile", arguments["profile"]]
        if arguments.get("report_dir"):
            cmd += ["--report-dir", arguments["report_dir"]]
        if arguments.get("ruleset"):
            cmd += ["--ruleset", arguments["ruleset"]]
        if arguments.get("exceptions_file"):
            cmd += ["--exceptions-file", arguments["exceptions_file"]]
        if arguments.get("log_level"):
            cmd += ["--log-level", arguments["log_level"]]
        if arguments.get("access_key_id") and arguments.get("secret_access_key"):
            cmd += ["--access-keys", "--access-key-id", arguments["access_key_id"], "--secret-access-key", arguments["secret_access_key"]]
            if arguments.get("session_token"):
                cmd += ["--session-token", arguments["session_token"]]
        return run_scoutsuite(cmd, env=env)

    raise ValueError(f"Tool not found: {name}")

async def main():
    async with stdio_server() as streams:
        await app.run(
            streams[0],
            streams[1],
            app.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
