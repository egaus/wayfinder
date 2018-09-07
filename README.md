# Wayfinder

Artificial Intelligence Agent to extract threat intelligence TTPs from feeds of malicious and benign event sources and automate threat hunting activities.

This project is a proof of concept using a knowledge-based approach at it's foundation.  It organizes a core knowledge base and analysis capabilities around various attack techniques, examples, tooling, and heuristic recognition.  Wayfinder uses various Machine Learning techniques based on the volume of data it has about a topic, allowing it to learn from a very small number of examples (e.g. 1 or more) to much more data (hundreds of thousands of examples).

## Useful files:
 - resources / parsed.zip: The pre-processed data used by the agent was derived from >3 months of Hybrid Analysis public feed logs.  A pre-processed version of these is included.
 - resources / proc_chain_summary.csv: Process chains learned by the agent after 3 months of data was analyzed.
 - resources / attack_lolbas_mapping.csv: Pre-requisite work done to map MITRE ATT&CK to LOLBAS and vice versa.  This data was folded into the ontology used by the agent.
 - resources / presentations: presentation material that more fully explains this project

### Next Steps:
 - Incorporate more knowledge into the ontology and enable the agent to recognize more objects like registry keys, important file paths, automate de-obfuscation steps, and gather more information about tool command line arguments and what they mean.
 - Add another dimension of feature analysis based on the newly recognized objects. 
 
***Windows Native Tool References:***
 - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands
 - https://ss64.com/nt/
 