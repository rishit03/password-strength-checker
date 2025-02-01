import re
import hashlib
import requests

# Function to check password strength
def check_password_strength(password):
    """Evaluates password strength based on security best practices."""
    
    strength = 0
    feedback = []

    # Minimum length check
    if len(password) < 8:
        feedback.append("❌ Password too short! Minimum 8 characters recommended.")
    elif len(password) >= 12:
        strength += 1

    # Upper and lower case check
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        strength += 1
    else:
        feedback.append("⚠️ Mix uppercase and lowercase letters for better security.")

    # Digit check
    if re.search(r'\d', password):
        strength += 1
    else:
        feedback.append("⚠️ Add at least one number to strengthen your password.")

    # Special character check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 1
    else:
        feedback.append("⚠️ Include special characters (!@#$ etc.) for extra security.")

    # Common weak password patterns
    weak_patterns = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome']
    if any(pattern in password.lower() for pattern in weak_patterns):
        feedback.append("❌ Avoid common weak passwords like 'password123' or 'qwerty'.")

    # Final strength evaluation
    if strength <= 2:
        rating = "🔴 WEAK"
    elif strength == 3:
        rating = "🟡 MEDIUM"
    else:
        rating = "🟢 STRONG"

    return rating, feedback

# Step 3: Function to Check Leaked Passwords
def check_pwned_password(password):
    """Checks if the password has been exposed in data breaches using HaveIBeenPwned API."""
    
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "⚠️ Unable to check password breach status."

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"⚠️ This password has been found in {count} breaches! DO NOT USE IT."

    return "✅ This password has not been found in known breaches."

# Step 4: User CLI Interaction
if __name__ == "__main__":
    print("\n🔐 Password Strength Checker 🔐")
    password = input("Enter a password to check: ")

    strength_rating, feedback_list = check_password_strength(password)
    print(f"\nPassword Strength: {strength_rating}")

    for feedback in feedback_list:
        print(feedback)

    print("\n🔍 Checking if password has been leaked in breaches...")
    breach_status = check_pwned_password(password)
    print(breach_status)
