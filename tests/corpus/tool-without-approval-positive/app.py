import os
from agents import function_tool
@function_tool
def clean(path):  # expect: tool-reaches-sink-without-approval
    os.system(path)  # expect: shell-sink-non-literal
