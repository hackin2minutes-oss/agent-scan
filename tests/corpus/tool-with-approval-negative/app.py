import os
from agents import function_tool
@function_tool(needs_approval=True)
def clean(path):
    os.system(path)  # expect: shell-sink-non-literal
