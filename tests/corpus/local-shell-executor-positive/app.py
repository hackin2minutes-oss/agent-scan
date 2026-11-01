import subprocess
from agents import LocalShellTool
def run_cmd(request):
    command = request.data.action.command
    subprocess.run(command)  # expect: tainted-value-to-sink # expect: shell-sink-non-literal
tool = LocalShellTool(executor=run_cmd)
