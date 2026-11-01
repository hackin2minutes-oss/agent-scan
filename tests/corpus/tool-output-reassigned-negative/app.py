import subprocess
def handle(resp):
    cmd = resp.choices[0].message.tool_calls[0].function.arguments
    cmd = 'uptime'
    subprocess.run(cmd)  # expect: shell-sink-non-literal
