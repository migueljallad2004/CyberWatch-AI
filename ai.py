import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = Groq(api_key=GROQ_API_KEY)

MODEL = "llama-3.3-70b-versatile"


def analyze_article(title, description):
    try:
        prompt = f"""
You are CyberWatch AI, a defensive cybersecurity threat analyst.

Analyze this cybersecurity news article.

TITLE:
{title}

DESCRIPTION:
{description}

You MUST return the answer EXACTLY in this format:

SUMMARY: <short explanation of what happened>

CATEGORY: <Vulnerability, Malware, Ransomware, Phishing, Data Breach, DDoS, Zero-Day, Cloud Security, Network Security, Mobile Security, or Other>

ATTACK_TYPE: <main attack or vulnerability type>

SEVERITY: <Critical, High, Medium, Low>

TARGET: <affected product, company, platform, users, or system>

IMPACT: <what could happen if successfully exploited>

CONFIDENCE: <High, Medium, Low>

RECOMMENDATIONS:
- <recommendation 1>
- <recommendation 2>
- <recommendation 3>

Severity guidance:

Critical:
Remote code execution, major zero-day, authentication bypass,
actively exploited critical vulnerability, destructive ransomware,
or vulnerabilities with extremely severe consequences.

High:
Privilege escalation, serious malware, credential theft,
major data breach, significant security bypass,
or vulnerabilities that can cause serious compromise.

Medium:
Attacks requiring special conditions, limited access,
moderate vulnerabilities, or lower-impact exploitation.

Low:
Minor vulnerabilities, informational issues,
or attacks with very limited impact.

Important rules:

- Always provide every field.
- Never write Unknown for severity if the article contains enough
  information to estimate severity.
- Do not invent specific facts.
- Judge severity based on the potential cybersecurity impact.
- If a CVSS score is mentioned, use it to help determine severity:
  9.0-10.0 = Critical
  7.0-8.9 = High
  4.0-6.9 = Medium
  0.1-3.9 = Low
"""

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are CyberWatch AI. "
                        "You analyze cybersecurity news and classify "
                        "threat severity accurately. "
                        "Follow the requested field names exactly."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=900
        )

        result = response.choices[0].message.content

        print("GROQ ANALYSIS SUCCESS")
        print(result)

        return result

    except Exception as e:
        print("GROQ ANALYSIS ERROR:", e)
        return "AI analysis failed."


def answer_threat_question(title, description, analysis, question):
    try:
        prompt = f"""
You are CyberWatch AI, a defensive cybersecurity assistant.

ARTICLE TITLE:
{title}

ARTICLE DESCRIPTION:
{description}

CYBERWATCH ANALYSIS:
{analysis}

USER QUESTION:
{question}

Answer clearly using simple English.

Use the article and analysis as your main information.

If the user asks whether they are affected:

- Explain which product, operating system, service,
  software, or device is affected.
- Explain what would make them vulnerable.
- Explain how they can check.
- Give defensive recommendations.

Do not automatically claim the user is affected.
Do not invent facts about the incident.
"""

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are CyberWatch AI, a defensive cybersecurity "
                        "assistant."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=700
        )

        return response.choices[0].message.content

    except Exception as e:
        print("GROQ ASK AI ERROR:", e)
        return "AI response failed."