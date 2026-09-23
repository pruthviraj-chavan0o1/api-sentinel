\# 🛡️ API Sentinel



\### API Security Testing \& Vulnerability Assessment Platform



API Sentinel is a web-based API security testing platform built with \*\*Java Spring Boot\*\* and \*\*MySQL\*\*.



It allows authenticated users to scan authorized HTTP/HTTPS APIs and analyze security configurations, HTTP security headers, potential vulnerabilities, and OWASP API Security Top 10 indicators.



\---



\## 🚀 Features



\### 🔐 Authentication \& Authorization



\- User registration

\- Secure BCrypt password hashing

\- JWT-based authentication

\- Stateless Spring Security configuration

\- Protected API endpoints

\- User-specific scan history



\### 🔎 API Security Scanner



API Sentinel analyzes an API endpoint and collects:



\- HTTP status code

\- Response time

\- Response size

\- Content type

\- Server information

\- Security headers

\- Potential security configuration issues



\### 🛡️ Security Header Analysis



The scanner checks for:



\- `X-Content-Type-Options`

\- `X-Frame-Options`

\- `Content-Security-Policy`

\- `Strict-Transport-Security`

\- `Referrer-Policy`



\### ⚠️ Vulnerability Detection



The scanner identifies indicators such as:



\- Missing HTTPS

\- Missing security headers

\- Server information disclosure

\- HTTP 5xx responses

\- Potential error information disclosure



\### 🔥 OWASP API Security Analysis



API Sentinel includes checks mapped to the \*\*OWASP API Security Top 10 (2023)\*\*.



| Category | Assessment |

|---|---|

| API1 | Broken Object Level Authorization |

| API2 | Broken Authentication |

| API3 | Broken Object Property Level Authorization |

| API4 | Unrestricted Resource Consumption |

| API5 | Broken Function Level Authorization |

| API6 | Unrestricted Access to Sensitive Business Flows |

| API7 | Server Side Request Forgery |

| API8 | Security Misconfiguration |

| API9 | Improper Inventory Management |

| API10 | Unsafe Consumption of APIs |



The scanner uses statuses such as:



\- `DETECTED`

\- `POTENTIAL`

\- `NOT\_DETECTED`

\- `NOT\_TESTABLE`



These statuses are used because a single HTTP request cannot conclusively prove every OWASP API vulnerability.



\---



\## 📊 Security Dashboard



The dashboard provides:



\- Security score

\- Risk level

\- Vulnerability count

\- OWASP finding count

\- Security headers

\- Scan information

\- OWASP summary



\### OWASP Summary



```text

┌────────────┬────────────┬────────────┬──────────────┐

│  DETECTED  │  POTENTIAL │ NOT DETECTED│ NOT TESTABLE │

│     1      │     4      │      2     │      3       │

└────────────┴────────────┴────────────┴──────────────┘
Built with Spring Boot to monitor and secure APIs.
