



1) We have a class:

curl_interpreter = cURLInterpreter(...) (find a better name if you have one)

The class might need to take api keys, tokens and any secret needed here. right?

2)  Suppose that request_as_test is a copy paste of the exact command of the curl request provided as text, we can do this:

tool = curl_interpreter.parse(request_as_text)

The parse function would be able to take on the most general cURL commands that can exist. The user can add description, input format and output format or other necessary information that makes sense with the essentials of HTTP/API requests.

3) Suppose the user wants to provide more documentation than just the request command (because the tool could have some metadata like description, input format and output format, etc )

tool = curl_interpreter.gpt_parse(some_docs)

This function would also take some budgeting parameters for the gpt call (using the guardrails). The prompt should be good enough to really capture the complexity of a general curl command.

Question: should we have a separate method to set a budget rright before gpt_parse, or should it be in the gpt_parse, or both (for robustness)?

4) Suppose that the user knows all the information and know the exact mapping for the command, then they can directly add as follows (even description, input format, output format)

tool = curl_interpreter.request_schema(type=GET, ...)

5) Then the request is made with any input needed. This could have some format validations, even leveraging input format if provided. The output could also contain some report of output validation, leveraging simple expected format for an API response, up to output format specified for the request

await tool.call(the_inputs)

6) You need to think about how API keys and tokens, passowrd etc can be fed to the class. different APIs require a different number of keys/tokens. This might need to be a flexible seuqnece of argument that we process with os.getenv or load_dotenv (we need to go the most general such that we adapt in any way the user wants to load the env. variables)


