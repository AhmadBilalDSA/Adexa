# prompts.py


PAYLOAD_PROMPT = """
Generate EXACTLY 3 SIMPLE SQL injection payloads.

STRICT RULES:
- Output ONLY one valid JSON array
- No markdown
- No explanations
- No text before or after JSON
- Stop immediately after the closing ]
- Generate EXACTLY 3 objects

Type must ONLY be:
- "boolean"
- "time"

PAYLOAD RULES:
- Every payload MUST be unique
- Every payload MUST be realistic
- Every payload MUST stay under 60 characters
- Keep every payload SHORT and SIMPLE
- Use only the techniques explicitly allowed below

ALLOWED TECHNIQUES:
- 1=1
- 2>1
- 'a'='a'
- ASCII('A')=65
- LENGTH('abc')=3
- SLEEP(3)
- SLEEP(5)

DO NOT USE:
- BENCHMARK
- SELECT
- UNION
- CASE
- IF
- INFORMATION_SCHEMA
- DATABASE()
- SCHEMA()
- SUBSTRING
- nested queries
- stacked queries
- encoded payloads
- double quotes
- escaped quotes
- malformed quotes
- destructive SQL

VALID OUTPUT EXAMPLE:
[
  {
    "payload":"1' AND 1=1 -- -",
    "type":"boolean"
  },
  {
    "payload":"1' AND ASCII('A')=65 -- -",
    "type":"boolean"
  },
  {
    "payload":"1' AND SLEEP(3) -- -",
    "type":"time"
  }
]

Return EXACTLY 3 objects.
OUTPUT ONLY THE JSON ARRAY.
Stop immediately after ].
"""


CORRUPTION_PROMPT = """
Corrupt EXACTLY 3 provided SQL injection payloads.

STRICT RULES:
- Output ONLY one valid JSON array
- No markdown
- No explanations
- No extra text
- Stop immediately after the closing ]
- Generate EXACTLY one corrupted object per input object

CRITICAL:
- broken_payload MUST actually be broken
- broken_payload MUST NOT be identical to original_payload
- Every corruption MUST visibly change the original payload
- Keep the original payload recognizable
- Make ONLY one simple corruption per payload
- Keep every payload SHORT

Failure type must ONLY be:
- "incomplete_statement"
- "malformed_syntax"
- "logical_error"
- "invalid_time_function"
- "boolean_no_effect"

VALID CORRUPTIONS:
- remove a closing parenthesis
- misspell AND
- misspell SLEEP
- break a comparison
- truncate the SQL comment
- change boolean logic so it no longer works

DO NOT:
- return an unchanged payload
- assign a failure label without actually breaking the payload
- rewrite the entire payload
- create complex SQL
- generate random garbage
- generate duplicate objects
- use SELECT
- use UNION
- use BENCHMARK
- use nested queries
- create destructive SQL

INVALID EXAMPLE:
{
  "broken_payload":"1' AND SLEEP(3) -- -",
  "failure_type":"invalid_time_function",
  "original_payload":"1' AND SLEEP(3) -- -"
}

The example above is INVALID because the payload was not changed.

VALID OUTPUT EXAMPLE:
[
  {
    "broken_payload":"1' AN D 1=1 -- -",
    "failure_type":"malformed_syntax",
    "original_payload":"1' AND 1=1 -- -"
  },
  {
    "broken_payload":"1' AND ASCII('A')==65 -- -",
    "failure_type":"logical_error",
    "original_payload":"1' AND ASCII('A')=65 -- -"
  },
  {
    "broken_payload":"1' AND SLEP(3) -- -",
    "failure_type":"invalid_time_function",
    "original_payload":"1' AND SLEEP(3) -- -"
  }
]

Return EXACTLY 3 objects.
OUTPUT ONLY THE JSON ARRAY.
Stop immediately after ].
"""


REPAIR_PROMPT = """
Repair EXACTLY 5 provided broken SQL injection payloads.

STRICT RULES:
- Output ONLY one valid JSON array
- No markdown
- No explanations outside JSON
- No extra text
- Stop immediately after the closing ]
- Generate EXACTLY one repair object per input object

Strategy must ONLY be:
- "SWITCH_BOOLEAN"
- "SWITCH_TIME"

CRITICAL RULES:
- repaired_payload MUST differ from broken_payload
- repaired_payload MUST use valid SQL syntax
- repaired_payload MUST stay under 40 characters
- repaired_payload MUST stay SHORT and SIMPLE
- Repair the failure using the simplest valid payload
- Do not copy an unchanged broken payload

SWITCH_BOOLEAN:
Use this strategy for boolean or syntax-related failures.

Allowed repairs include:
- 1' AND 1=1 -- -
- 1' AND 2>1 -- -
- 1' AND 'a'='a' -- -
- 1' AND ASCII('A')=65 -- -
- 1' AND LENGTH('abc')=3 -- -

SWITCH_TIME:
Use this strategy for timing-related failures.

Allowed repairs include:
- 1' AND SLEEP(3) -- -
- 1' AND SLEEP(5) -- -

DO NOT USE:
- CHANGE_QUOTES
- BENCHMARK
- SELECT
- UNION
- CASE
- IF
- INFORMATION_SCHEMA
- DATABASE()
- SCHEMA()
- SUBSTRING
- nested queries
- stacked queries
- double quotes
- escaped quotes
- SLEEP(0)
- malformed SQL
- unchanged payloads
- fake SQL
- destructive SQL

EXPLANATION RULES:
- explanation MUST be one short sentence
- explanation MUST contain at least 4 words
- Keep explanation concise
- Do not say "Already valid"
- Do not say "No change needed"

VALID OUTPUT EXAMPLE:
[
  {
    "broken_payload":"1' AN D 1=1 -- -",
    "failure_type":"malformed_syntax",
    "strategy":"SWITCH_BOOLEAN",
    "repaired_payload":"1' AND 2>1 -- -",
    "explanation":"Fixed the malformed boolean syntax."
  },
  {
    "broken_payload":"1' AND 1==1 -- -",
    "failure_type":"logical_error",
    "strategy":"SWITCH_BOOLEAN",
    "repaired_payload":"1' AND 1=1 -- -",
    "explanation":"Corrected the invalid boolean comparison."
  },
  {
    "broken_payload":"1' AND SLEP(3) -- -",
    "failure_type":"invalid_time_function",
    "strategy":"SWITCH_TIME",
    "repaired_payload":"1' AND SLEEP(3) -- -",
    "explanation":"Corrected the invalid timing function."
  }
]

Return EXACTLY 5 objects.
OUTPUT ONLY THE JSON ARRAY.
Stop immediately after ].
"""