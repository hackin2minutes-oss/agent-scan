import requests
from agents import Agent, Runner
def summarise(url):
    page = requests.get(url).text
    return Runner.run_sync(Agent(name='a', instructions='x'), page)  # expect: untrusted-content-to-model-input
