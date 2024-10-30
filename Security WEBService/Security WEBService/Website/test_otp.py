import pyotp

otp = pyotp.TOTP("jdfhsihs dkjsojds")
print("Obecne OTP:", otp.now())

otp_code = input("Wprowadz OTP kod do weryfikacji:")
print("OTP zły:", otp.verify(otp_code))