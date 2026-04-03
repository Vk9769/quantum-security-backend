import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load env
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


def send_email(to_email: str, otp: str):
    """
    Send OTP email using Gmail SMTP (Professional HTML Template)
    """
    try:
        subject = "🔐 Your Verification Code"

        # ✨ Professional HTML Email
        html_body = f"""
        <html>
        <body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;">
            <div style="max-width:500px;margin:40px auto;background:#ffffff;border-radius:12px;
                        box-shadow:0 4px 12px rgba(0,0,0,0.1);padding:30px;text-align:center;">

                <h2 style="color:#111827;margin-bottom:10px;">
                    🔐 Verification Code
                </h2>

                <p style="color:#6b7280;font-size:14px;">
                    Use the OTP below to complete your request
                </p>

                <div style="margin:25px 0;">
                    <span style="
                        display:inline-block;
                        font-size:32px;
                        font-weight:bold;
                        letter-spacing:6px;
                        color:#2563eb;
                        background:#eff6ff;
                        padding:12px 24px;
                        border-radius:8px;
                    ">
                        {otp}
                    </span>
                </div>

                <p style="color:#374151;font-size:14px;">
                    This code is valid for <b>5 minutes</b>.
                </p>

                <hr style="margin:25px 0;border:none;border-top:1px solid #e5e7eb;">

                <p style="font-size:12px;color:#9ca3af;">
                    If you didn’t request this, you can safely ignore this email.
                </p>

                <p style="font-size:12px;color:#6b7280;margin-top:10px;">
                    © 2026 Quantum Security Platform
                </p>
            </div>
        </body>
        </html>
        """

        # Plain text fallback
        text_body = f"""
Your OTP is: {otp}

This OTP is valid for 5 minutes.

If you didn't request this, ignore this email.

- Quantum Security Team
"""

        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = to_email

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # SMTP
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()

        print(f"✅ Email sent to {to_email}")

    except smtplib.SMTPAuthenticationError:
        print("❌ Authentication failed (check App Password)")

    except Exception as e:
        print(f"❌ Email error: {e}")