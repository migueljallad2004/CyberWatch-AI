from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv

from ai import analyze_article, answer_threat_question

from datetime import datetime, timezone, timedelta
import feedparser
import resend
import requests
import os
import re
import base64
import secrets
import smtplib
from email.message import EmailMessage


load_dotenv()

NEWS_API_KEY = os.getenv("NEWS_API_KEY")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
APP_USERNAME = os.getenv("APP_USERNAME")
APP_PASSWORD = os.getenv("APP_PASSWORD")
FROM_EMAIL = os.getenv(
    "FROM_EMAIL",
    "CyberWatch AI <onboarding@resend.dev>"
)

resend.api_key = RESEND_API_KEY


security = HTTPBasic()


def require_auth(
    credentials: HTTPBasicCredentials = Depends(security)
):
    if not APP_USERNAME or not APP_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Private access is not configured."
        )

    username_ok = secrets.compare_digest(
        credentials.username,
        APP_USERNAME
    )
    password_ok = secrets.compare_digest(
        credentials.password,
        APP_PASSWORD
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Basic"}
        )

    return credentials.username


app = FastAPI(
    title="CyberWatch AI",
    description="Multi-source AI Cyber Threat Intelligence",
    version="6.1",
    dependencies=[Depends(require_auth)]
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


FRONTEND_FILE = os.path.join(
    os.path.dirname(__file__),
    "frontend",
    "index.html"
)


NEWS_API_URL = "https://newsapi.org/v2/everything"

THE_HACKER_NEWS_RSS = (
    "https://feeds.feedburner.com/TheHackersNews"
)

BLEEPING_COMPUTER_RSS = (
    "https://www.bleepingcomputer.com/feed/"
)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


SUPPORTED_SOURCES = [
    "newsapi",
    "the hacker news",
    "bleepingcomputer",
    "cisa",
    "nvd"
]


class EmailReport(BaseModel):
    recipients: list[EmailStr]
    subject: str = "CyberWatch AI Threat Report"
    message: str = ""
    content: str
    attach_report: bool = True


class AskRequest(BaseModel):
    title: str
    description: str
    analysis: str
    question: str


@app.get("/")
def home():

    return FileResponse(
        FRONTEND_FILE
    )


@app.get("/api/status")
def api_status():

    return {
        "name": "CyberWatch AI",

        "status": "Running",

        "version": "6.0",

        "ai": "Ollama Cloud AI",

        "sources": [
            "NewsAPI",
            "The Hacker News",
            "BleepingComputer",
            "CISA",
            "NVD"
        ],

        "email_enabled": bool(
            RESEND_API_KEY
            or
            (EMAIL_ADDRESS and EMAIL_APP_PASSWORD)
        ),

        "ollama_enabled": bool(
            OLLAMA_API_KEY
        )
    }


def parse_date(value):

    try:

        date = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )

    except Exception:

        raise Exception(
            "Invalid date format."
        )


    if date.tzinfo is None:

        date = date.replace(
            tzinfo=timezone.utc
        )


    return date.astimezone(
        timezone.utc
    )


def parse_csv(value):

    if not value:
        return []


    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def strip_html(value):

    if not value:
        return ""


    value = re.sub(
        r"<[^>]+>",
        " ",
        value
    )


    value = re.sub(
        r"\s+",
        " ",
        value
    )


    return value.strip()


def matches_filters(
    title,
    description,
    attack_types,
    platforms
):

    text = (
        f"{title or ''} "
        f"{description or ''}"
    ).lower()


    if attack_types:

        attack_match = any(
            item.lower() in text
            for item in attack_types
        )


        if not attack_match:

            return False


    if platforms:

        platform_match = any(
            item.lower() in text
            for item in platforms
        )


        if not platform_match:

            return False


    return True


def date_in_range(
    value,
    start,
    end
):

    if not value:

        return True


    try:

        date = parse_date(
            value
        )


        return (
            start
            <=
            date
            <=
            end
        )


    except Exception:

        return True


def validate_date_range(
    start,
    end
):

    if start >= end:

        raise Exception(
            "From must be earlier than To."
        )


    now = datetime.now(
        timezone.utc
    )


    if end > (
        now
        +
        timedelta(minutes=5)
    ):

        raise Exception(
            "The To date cannot be in the future."
        )


    if (
        end - start
    ) > timedelta(days=30):

        raise Exception(
            "Search range cannot exceed 30 days."
        )


def build_newsapi_query(
    attack_types,
    platforms
):

    attack_query = ""

    platform_query = ""


    if attack_types:

        attack_query = (
            "("
            +
            " OR ".join(
                f'"{item}"'
                for item in attack_types
            )
            +
            ")"
        )


    if platforms:

        platform_query = (
            "("
            +
            " OR ".join(
                f'"{item}"'
                for item in platforms
            )
            +
            ")"
        )


    if (
        attack_query
        and
        platform_query
    ):

        return (
            attack_query
            +
            " AND "
            +
            platform_query
        )


    if attack_query:

        return attack_query


    if platform_query:

        base_query = (
            '"cyber attack" OR '
            '"cybersecurity" OR '
            '"ransomware" OR '
            '"malware" OR '
            '"data breach" OR '
            '"security vulnerability"'
        )


        return (
            "("
            +
            base_query
            +
            ") AND "
            +
            platform_query
        )


    return (
        '"cyber attack" OR '
        '"cyberattack" OR '
        '"ransomware" OR '
        '"malware" OR '
        '"phishing" OR '
        '"data breach" OR '
        '"zero-day" OR '
        '"DDoS" OR '
        '"security vulnerability"'
    )


def fetch_newsapi(
    start,
    end,
    attack_types,
    platforms,
    limit
):

    if not NEWS_API_KEY:

        raise Exception(
            "NEWS_API_KEY is missing."
        )


    response = requests.get(

        NEWS_API_URL,

        params={

            "q":
                build_newsapi_query(
                    attack_types,
                    platforms
                ),

            "searchIn":
                "title,description",

            "language":
                "en",

            "sortBy":
                "publishedAt",

            "pageSize":
                limit,

            "from":
                start.isoformat(),

            "to":
                end.isoformat()
        },

        headers={
            "X-Api-Key":
                NEWS_API_KEY
        },

        timeout=20
    )


    response.raise_for_status()


    data = response.json()


    if (
        data.get("status")
        !=
        "ok"
    ):

        raise Exception(

            data.get(
                "message",
                "NewsAPI returned an error."
            )

        )


    results = []


    for item in data.get(
        "articles",
        []
    ):

        title = item.get(
            "title"
        )


        if not title:

            continue


        description = (
            item.get(
                "description"
            )
            or
            "No description available."
        )


        results.append({

            "title":
                title,

            "description":
                description,

            "source":
                item.get(
                    "source",
                    {}
                ).get(
                    "name",
                    "NewsAPI"
                ),

            "source_group":
                "NewsAPI",

            "source_type":
                "News",

            "published_at":
                item.get(
                    "publishedAt"
                ),

            "url":
                item.get(
                    "url"
                ),

            "cve":
                None,

            "cvss_score":
                None,

            "cvss_severity":
                None,

            "known_exploited":
                False

        })


    return results


def parse_feed_date(entry):

    if entry.get(
        "published_parsed"
    ):

        return datetime(

            *entry.published_parsed[:6],

            tzinfo=timezone.utc

        ).isoformat()


    if entry.get(
        "updated_parsed"
    ):

        return datetime(

            *entry.updated_parsed[:6],

            tzinfo=timezone.utc

        ).isoformat()


    return None


def fetch_rss_source(
    feed_url,
    source_name,
    start,
    end,
    attack_types,
    platforms,
    limit
):

    feed = feedparser.parse(
        feed_url
    )


    if (
        getattr(
            feed,
            "bozo",
            False
        )
        and
        not feed.entries
    ):

        raise Exception(
            "RSS feed could not be read."
        )


    results = []


    for entry in feed.entries:

        title = (
            entry.get(
                "title"
            )
            or
            "Untitled"
        )


        description = strip_html(

            entry.get(
                "summary"
            )
            or
            entry.get(
                "description"
            )
            or
            ""

        )


        published = parse_feed_date(
            entry
        )


        if not date_in_range(
            published,
            start,
            end
        ):

            continue


        if not matches_filters(
            title,
            description,
            attack_types,
            platforms
        ):

            continue


        results.append({

            "title":
                title,

            "description":
                description,

            "source":
                source_name,

            "source_group":
                source_name,

            "source_type":
                "Cybersecurity News",

            "published_at":
                published,

            "url":
                entry.get(
                    "link"
                ),

            "cve":
                None,

            "cvss_score":
                None,

            "cvss_severity":
                None,

            "known_exploited":
                False

        })


        if (
            len(results)
            >=
            limit
        ):

            break


    return results


def fetch_cisa(
    start,
    end,
    attack_types,
    platforms,
    limit
):

    response = requests.get(
        CISA_KEV_URL,
        timeout=20
    )


    response.raise_for_status()


    data = response.json()


    results = []


    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )


    for item in reversed(
        vulnerabilities
    ):

        date_added = item.get(
            "dateAdded"
        )


        if not date_added:

            continue


        try:

            published = datetime.fromisoformat(
                date_added
            ).replace(
                tzinfo=timezone.utc
            )


        except Exception:

            continue


        if not (
            start
            <=
            published
            <=
            end
        ):

            continue


        cve = item.get(
            "cveID",
            ""
        )


        vendor = item.get(
            "vendorProject",
            ""
        )


        product = item.get(
            "product",
            ""
        )


        vulnerability_name = item.get(
            "vulnerabilityName",
            ""
        )


        description = item.get(
            "shortDescription",
            ""
        )


        required_action = item.get(
            "requiredAction",
            ""
        )


        ransomware_use = item.get(
            "knownRansomwareCampaignUse",
            ""
        )


        full_description = (

            f"{vendor} {product}. "

            f"{description} "

            f"Required action: "
            f"{required_action}. "

            f"Known ransomware use: "
            f"{ransomware_use}."

        )


        title = (
            f"{cve} - "
            f"{vulnerability_name}"
        )


        if not matches_filters(
            title,
            full_description,
            attack_types,
            platforms
        ):

            continue


        results.append({

            "title":
                title,

            "description":
                full_description,

            "source":
                "CISA",

            "source_group":
                "CISA",

            "source_type":
                "Known Exploited Vulnerability",

            "published_at":
                published.isoformat(),

            "url":
                (
                    "https://www.cisa.gov/"
                    "known-exploited-vulnerabilities-catalog"
                ),

            "cve":
                cve,

            "vendor":
                vendor,

            "product":
                product,

            "cvss_score":
                None,

            "cvss_severity":
                None,

            "known_exploited":
                True

        })


        if (
            len(results)
            >=
            limit
        ):

            break


    return results


def get_nvd_cvss(cve):

    metrics = cve.get(
        "metrics",
        {}
    )


    versions = [

        "cvssMetricV40",

        "cvssMetricV31",

        "cvssMetricV30",

        "cvssMetricV2"

    ]


    for name in versions:

        metric_list = metrics.get(
            name,
            []
        )


        if not metric_list:

            continue


        metric = metric_list[0]


        cvss_data = metric.get(
            "cvssData",
            {}
        )


        return {

            "score":
                cvss_data.get(
                    "baseScore"
                ),

            "severity":
                (
                    cvss_data.get(
                        "baseSeverity"
                    )
                    or
                    metric.get(
                        "baseSeverity"
                    )
                )

        }


    return {

        "score":
            None,

        "severity":
            None

    }


def fetch_nvd(
    start,
    end,
    attack_types,
    platforms,
    limit
):

    response = requests.get(

        NVD_API_URL,

        params={

            "pubStartDate":
                start.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                ),

            "pubEndDate":
                end.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                ),

            "resultsPerPage":
                min(
                    max(
                        limit * 5,
                        20
                    ),
                    100
                )

        },

        timeout=30

    )


    response.raise_for_status()


    data = response.json()


    results = []


    for wrapper in data.get(
        "vulnerabilities",
        []
    ):

        cve = wrapper.get(
            "cve",
            {}
        )


        cve_id = cve.get(
            "id",
            ""
        )


        description = ""


        for item in cve.get(
            "descriptions",
            []
        ):

            if (
                item.get(
                    "lang"
                )
                ==
                "en"
            ):

                description = item.get(
                    "value",
                    ""
                )


                break


        if not matches_filters(
            cve_id,
            description,
            attack_types,
            platforms
        ):

            continue


        cvss = get_nvd_cvss(
            cve
        )


        results.append({

            "title":
                (
                    cve_id
                    +
                    " - NVD Vulnerability"
                ),

            "description":
                description,

            "source":
                "NVD",

            "source_group":
                "NVD",

            "source_type":
                "Vulnerability Database",

            "published_at":
                cve.get(
                    "published"
                ),

            "url":
                (
                    "https://nvd.nist.gov/"
                    "vuln/detail/"
                    +
                    cve_id
                ),

            "cve":
                cve_id,

            "cvss_score":
                cvss[
                    "score"
                ],

            "cvss_severity":
                cvss[
                    "severity"
                ],

            "known_exploited":
                False

        })


        if (
            len(results)
            >=
            limit
        ):

            break


    return results


def remove_duplicates(
    articles
):

    unique = []

    seen_urls = set()

    seen_titles = set()


    for article in articles:

        title = (
            article.get(
                "title",
                ""
            )
            .strip()
            .lower()
        )


        url = (
            article.get(
                "url",
                ""
            )
            .strip()
            .lower()
        )


        if (
            url
            and
            url in seen_urls
        ):

            continue


        if (
            title
            and
            title in seen_titles
        ):

            continue


        if url:

            seen_urls.add(
                url
            )


        if title:

            seen_titles.add(
                title
            )


        unique.append(
            article
        )


    return unique


def sort_date_value(
    article
):

    value = article.get(
        "published_at"
    )


    if not value:

        return datetime.min.replace(
            tzinfo=timezone.utc
        )


    try:

        return parse_date(
            value
        )


    except Exception:

        return datetime.min.replace(
            tzinfo=timezone.utc
        )


@app.get("/news")
def get_news(
    from_date: str,
    to_date: str,
    attack_types: str = "",
    platforms: str = "",
    sources: str = "",
    limit: int = 20
):

    try:

        start = parse_date(
            from_date
        )


        end = parse_date(
            to_date
        )


        validate_date_range(
            start,
            end
        )


        attack_list = [

            item

            for item in parse_csv(
                attack_types
            )

            if (
                item.lower()
                !=
                "all"
            )

        ]


        platform_list = [

            item

            for item in parse_csv(
                platforms
            )

            if (
                item.lower()
                !=
                "all"
            )

        ]


        source_list = [

            item.lower()

            for item in parse_csv(
                sources
            )

        ]


        if (
            not source_list
            or
            "all" in source_list
        ):

            source_list = (
                SUPPORTED_SOURCES.copy()
            )


        source_list = [

            source

            for source in source_list

            if source in SUPPORTED_SOURCES

        ]


        if not source_list:

            raise Exception(
                "No valid source selected."
            )


        limit = max(
            1,
            min(
                limit,
                50
            )
        )


        combined = []

        errors = []


        if (
            "newsapi"
            in source_list
        ):

            try:

                combined.extend(

                    fetch_newsapi(
                        start,
                        end,
                        attack_list,
                        platform_list,
                        limit
                    )

                )


            except Exception as error:

                errors.append(
                    "NewsAPI: "
                    +
                    str(error)
                )


        if (
            "the hacker news"
            in source_list
        ):

            try:

                combined.extend(

                    fetch_rss_source(

                        THE_HACKER_NEWS_RSS,

                        "The Hacker News",

                        start,

                        end,

                        attack_list,

                        platform_list,

                        limit

                    )

                )


            except Exception as error:

                errors.append(
                    "The Hacker News: "
                    +
                    str(error)
                )


        if (
            "bleepingcomputer"
            in source_list
        ):

            try:

                combined.extend(

                    fetch_rss_source(

                        BLEEPING_COMPUTER_RSS,

                        "BleepingComputer",

                        start,

                        end,

                        attack_list,

                        platform_list,

                        limit

                    )

                )


            except Exception as error:

                errors.append(
                    "BleepingComputer: "
                    +
                    str(error)
                )


        if (
            "cisa"
            in source_list
        ):

            try:

                combined.extend(

                    fetch_cisa(

                        start,

                        end,

                        attack_list,

                        platform_list,

                        limit

                    )

                )


            except Exception as error:

                errors.append(
                    "CISA: "
                    +
                    str(error)
                )


        if (
            "nvd"
            in source_list
        ):

            try:

                combined.extend(

                    fetch_nvd(

                        start,

                        end,

                        attack_list,

                        platform_list,

                        limit

                    )

                )


            except Exception as error:

                errors.append(
                    "NVD: "
                    +
                    str(error)
                )


        combined = remove_duplicates(
            combined
        )


        combined.sort(
            key=sort_date_value,
            reverse=True
        )


        combined = combined[
            :limit
        ]


        return {

            "status":
                "ok",

            "total":
                len(
                    combined
                ),

            "attack_types":
                attack_list,

            "platforms":
                platform_list,

            "sources_used":
                source_list,

            "source_errors":
                errors,

            "articles":
                combined

        }


    except Exception as error:

        return {

            "status":
                "error",

            "message":
                str(error)

        }


@app.get("/analyze")
def analyze(
    title: str,
    description: str
):

    try:

        result = analyze_article(
            title,
            description
        )


        return {

            "status":
                "ok",

            "analysis":
                result

        }


    except Exception as error:

        return {

            "status":
                "error",

            "message":
                str(error)

        }


@app.post("/ask")
def ask_ai(
    request: AskRequest
):

    try:

        question = (
            request.question
            .strip()
        )


        if not question:

            return {

                "status":
                    "error",

                "message":
                    "Question cannot be empty."

            }


        answer = answer_threat_question(

            request.title,

            request.description,

            request.analysis,

            question

        )


        return {

            "status":
                "ok",

            "answer":
                answer

        }


    except Exception as error:

        return {

            "status":
                "error",

            "message":
                str(error)

        }


def send_email_with_gmail(
    recipients,
    subject,
    message,
    content,
    attach_report
):
    email_body = (
        message.strip()
        or
        "A CyberWatch AI threat report is included below."
    )

    if not attach_report:
        email_body = (
            email_body
            + "\n\n"
            + content
        ).strip()

    email = EmailMessage()
    email["From"] = (
        f"CyberWatch AI <{EMAIL_ADDRESS}>"
    )
    email["To"] = ", ".join(recipients)
    email["Subject"] = subject
    email.set_content(email_body)

    if attach_report:
        email.add_attachment(
            content.encode("utf-8"),
            maintype="text",
            subtype="plain",
            filename="cyberwatch-threat-report.txt"
        )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=30
    ) as server:
        server.login(
            EMAIL_ADDRESS,
            EMAIL_APP_PASSWORD
        )
        server.send_message(email)

    return {
        "provider": "gmail",
        "recipients": len(recipients)
    }


def send_email_with_resend(
    recipients,
    subject,
    message,
    content,
    attach_report
):

    if EMAIL_ADDRESS and EMAIL_APP_PASSWORD:
        return send_email_with_gmail(
            recipients,
            subject,
            message,
            content,
            attach_report
        )

    if not RESEND_API_KEY:
        raise Exception(
            "Email delivery is not configured."
        )

    email_body = (
        message.strip()
        or
        "A CyberWatch AI threat report is included below."
    )

    payload = {
        "from": FROM_EMAIL,
        "to": recipients,
        "subject": subject
    }

    if attach_report:
        payload["text"] = email_body
        payload["attachments"] = [
            {
                "content": base64.b64encode(
                    content.encode("utf-8")
                ).decode("ascii"),
                "filename": "cyberwatch-threat-report.txt"
            }
        ]
    else:
        payload["text"] = (
            email_body
            + "\n\n"
            + content
        ).strip()

    try:
        response = resend.Emails.send(payload)

        print(
            "RESEND EMAIL SUCCESS:",
            response
        )

        return response

    except Exception as error:
        print(
            "RESEND EMAIL ERROR:",
            error
        )

        raise Exception(
            str(error)
        )


@app.post("/send-email")
def send_email_report(
    report: EmailReport
):

    try:
        recipients = list(dict.fromkeys(
            str(item).strip()
            for item in report.recipients
            if str(item).strip()
        ))

        subject = report.subject.strip()
        message = report.message.strip()
        content = report.content.strip()

        if not recipients:
            return {
                "status": "error",
                "message": "At least one recipient is required."
            }

        if len(recipients) > 50:
            return {
                "status": "error",
                "message": "A maximum of 50 recipients is allowed."
            }

        if not subject:
            subject = "CyberWatch AI Threat Report"

        if not content:
            return {
                "status": "error",
                "message": "Email report is empty."
            }

        send_email_with_resend(
            recipients,
            subject,
            message,
            content,
            report.attach_report
        )

        return {
            "status": "ok",
            "message": "Email sent successfully.",
            "recipients": len(recipients)
        }

    except Exception as error:
        return {
            "status": "error",
            "message": str(error)
        }

