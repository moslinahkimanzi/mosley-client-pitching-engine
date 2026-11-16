#!/usr/bin/env python3
"""Send one SMTP diagnostic message to the configured MCAS administrator.

Run after loading the private .env:
  set -a && source .env && set +a
  python test_email_delivery.py

This script never prints SMTP credentials and never reads any inbox.
"""
import os
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage


def main() -> int:
    host = os.getenv("MCAS_EMAIL_SMTP_HOST", "").strip()
    sender = os.getenv("MCAS_EMAIL_FROM", "").strip()
    username = os.getenv("MCAS_EMAIL_SMTP_USERNAME", "").strip()
    password = os.getenv("MCAS_EMAIL_SMTP_PASSWORD", "").strip()
    port_text = os.getenv("MCAS_EMAIL_SMTP_PORT", "587").strip()
    use_ssl = os.getenv("MCAS_EMAIL_SMTP_USE_SSL", "false").strip().lower() == "true"
    use_starttls = os.getenv("MCAS_EMAIL_SMTP_STARTTLS", "true").strip().lower() == "true"
    admins = [
        item.strip() for item in os.getenv("MCAS_ADMIN_EMAILS", "").split(",")
        if item.strip()
    ]
    recipient = admins[0] if admins else sender

    print("MCAS SMTP diagnostic")
    print("SMTP host configured:", bool(host))
    print("SMTP username configured:", bool(username))
    print("SMTP password configured:", bool(password))
    print("Sender configured:", bool(sender))
    print("Administrator recipient configured:", bool(recipient))
    if not host or not sender or not recipient:
        print("FAILED: Set MCAS_EMAIL_SMTP_HOST, MCAS_EMAIL_FROM and MCAS_ADMIN_EMAILS in .env.")
        return 2
    if bool(username) != bool(password):
        print("FAILED: SMTP username and password must either both be set or both be empty.")
        return 2

    try:
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("FAILED: MCAS_EMAIL_SMTP_PORT must be a valid TCP port.")
        return 2

    gmail_host = host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"}
    if gmail_host:
        if not username or not password:
            print("FAILED: Gmail SMTP requires an account username and Google App Password.")
            return 2
        if port == 587 and (use_ssl or not use_starttls):
            print("FAILED: Gmail port 587 requires USE_SSL=false and STARTTLS=true.")
            return 2
        if port == 465 and (not use_ssl or use_starttls):
            print("FAILED: Gmail port 465 requires USE_SSL=true and STARTTLS=false.")
            return 2
        if port not in {465, 587}:
            print("FAILED: Use Gmail SMTP port 465 or 587.")
            return 2
        password = "".join(password.split())

    if use_ssl and use_starttls:
        print("FAILED: Choose implicit SSL or STARTTLS, not both.")
        return 2

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "MCAS SMTP delivery test"
    message.set_content(
        "This is a diagnostic email from your MCAS installation.\\n\\n"
        "It confirms that the configured SMTP server accepted a test message. "
        "It does not contain an account-verification link.\\n"
        "Time: " + datetime.now(timezone.utc).isoformat()
    )

    try:
        smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        kwargs = {"host": host, "port": port, "timeout": 15}
        if use_ssl:
            kwargs["context"] = ssl.create_default_context()
        with smtp_class(**kwargs) as server:
            if not use_ssl and use_starttls:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if username:
                server.login(username, password)
            refused = server.send_message(message)

        if refused:
            codes = sorted({
                int(reply[0]) for reply in refused.values()
                if isinstance(reply, tuple) and reply
            })
            print("FAILED: SMTP refused the test message. SMTP code(s):",
                  ", ".join(map(str, codes)) or "unknown")
            return 1

        print("SUCCESS: SMTP server accepted the test message.")
        print("Check the configured administrator inbox, including Spam and Promotions.")
        print("Note: SMTP acceptance does not guarantee final inbox delivery.")
        return 0

    except (OSError, smtplib.SMTPException, ValueError) as exc:
        code = getattr(exc, "smtp_code", None)
        print("FAILED: SMTP connection or delivery failed.")
        print("Error type:", type(exc).__name__)
        if code is not None:
            print("SMTP status code:", code)
        print("Safe diagnostic:", str(exc)[:300])
        print("No password or verification token was printed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
