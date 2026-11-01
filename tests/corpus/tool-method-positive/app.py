from langchain_core.tools import tool
@tool
def run_it(cmd):
    return cmd
def handle(user_input):
    run_it.invoke(user_input)  # expect: tool-sink-non-literal
