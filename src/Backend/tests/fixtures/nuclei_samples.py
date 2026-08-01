"""JSONL fixture strings for Nuclei wrapper tests."""

SAMPLE_NUCLEI_JSONL_MULTI = (
    '{"template-id":"cve-2021-41773","info":{"name":"Apache HTTP Server Path Traversal",'
    '"severity":"critical","tags":["cve","apache","rce"],'
    '"description":"A flaw was found in Apache HTTP Server.",'
    '"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]},'
    '"type":"http","host":"http://192.168.1.10:80",'
    '"matched-at":"http://192.168.1.10:80/cgi-bin/.%2e/.%2e/etc/passwd",'
    '"extracted-results":["root:x:0:0:root:/root:/bin/bash"],'
    '"ip":"192.168.1.10","timestamp":"2024-01-15T14:30:00Z"}\n'
    '{"template-id":"cve-2023-22515","info":{"name":"Confluence Auth Bypass",'
    '"severity":"high","tags":["cve","confluence"],'
    '"description":"Broken access control in Confluence.",'
    '"reference":["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"]},'
    '"type":"http","host":"http://192.168.1.10:8090",'
    '"matched-at":"http://192.168.1.10:8090/setup/setupadministrator.action",'
    '"extracted-results":[],"ip":"192.168.1.10","timestamp":"2024-01-15T14:31:00Z"}\n'
)

SAMPLE_NUCLEI_JSONL_EMPTY = ""

SAMPLE_NUCLEI_JSONL_MALFORMED = (
    '{"template-id":"cve-2021-41773","info":{"name":"Apache Path Traversal",'
    '"severity":"critical","tags":["cve"]},'
    '"type":"http","host":"http://192.168.1.10:80",'
    '"matched-at":"http://192.168.1.10:80/traversal"}\n'
    "THIS IS NOT VALID JSON\n"
    '{"template-id":"tech-detect","info":{"name":"Tech Detect",'
    '"severity":"info","tags":["tech"]},'
    '"type":"http","host":"http://192.168.1.10:80",'
    '"matched-at":"http://192.168.1.10:80/"}\n'
)

SAMPLE_NUCLEI_JSONL_UNKNOWN_SEVERITY = (
    '{"template-id":"custom-check","info":{"name":"Custom Check",'
    '"severity":"exotic","tags":[]},'
    '"type":"http","host":"http://10.0.0.1:80",'
    '"matched-at":"http://10.0.0.1:80/test"}\n'
)

SAMPLE_NUCLEI_JSONL_MISSING_REQUIRED = (
    '{"info":{"name":"No Template ID","severity":"low"},'
    '"host":"http://10.0.0.1","matched-at":"http://10.0.0.1/"}\n'
    '{"template-id":"has-id","info":{"severity":"low"},'
    '"host":"http://10.0.0.1","matched-at":"http://10.0.0.1/"}\n'
    '{"template-id":"ok","info":{"name":"Valid Finding","severity":"medium"},'
    '"host":"http://10.0.0.1","matched-at":"http://10.0.0.1/found"}\n'
)

SAMPLE_NUCLEI_JSONL_OPTIONAL_DEFAULTS = (
    '{"template-id":"minimal","info":{"name":"Minimal Finding",'
    '"severity":"low"},"host":"http://10.0.0.1",'
    '"matched-at":"http://10.0.0.1/minimal"}\n'
)
