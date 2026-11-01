from langchain_core.tools import tool
@tool
def run_it(cmd):
    return cmd
run_it.invoke('status')
