from agents import Runner
Runner.run(agent, 'hi', max_turns=None)  # expect: unbounded-agent-loop
