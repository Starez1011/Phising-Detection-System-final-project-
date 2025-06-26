from flask_mail import Message
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(mail, to, otp):
    msg = Message(
        subject="Your OTP Verification Code",
        recipients=[to],
        body=f"Your OTP code is: {otp}"
    )
    mail.send(msg) 