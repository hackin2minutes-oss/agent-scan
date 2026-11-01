import subprocess, shlex
def handle(resp):
    args = resp.choices[0].message.tool_calls[0].function.arguments
    subprocess.run(shlex.quote(args))  # expect: shell-sink-non-literal
