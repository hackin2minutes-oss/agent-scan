import subprocess
def handle(resp):
    args = resp.choices[0].message.tool_calls[0].function.arguments
    subprocess.run(args)  # expect: tainted-value-to-sink # expect: shell-sink-non-literal
