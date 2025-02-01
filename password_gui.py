import re
import hashlib
import requests
import tkinter as tk
from tkinter import messagebox

# Function to check password strength
def check_password_strength(password):
    """Evaluates password strength based on security best practices."""
    strength = 0
    feedback = []

    if len(password) < 8:
        feedback.append("❌ Too short! Use at least 8 characters.")
    elif len(password) >= 12:
        strength += 1

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        strength += 1
    else:
        feedback.append("⚠️ Use both uppercase and lowercase letters.")

    if re.search(r'\d', password):
        strength += 1
    else:
        feedback.append("⚠️ Add at least one number.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 1
    else:
        feedback.append("⚠️ Include special characters (!@#$ etc.).")

    weak_patterns = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome']
    if any(pattern in password.lower() for pattern in weak_patterns):
        feedback.append("❌ Avoid common weak passwords like 'password123'.")

    if strength <= 2:
        return "🔴 WEAK", feedback
    elif strength == 3:
        return "🟡 MEDIUM", feedback
    else:
        return "🟢 STRONG", feedback

# Function to check leaked passwords using HaveIBeenPwned API
def check_pwned_password(password):
    """Checks if the password has been exposed in data breaches."""
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "⚠️ Unable to check password breaches."

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"⚠️ This password was found in {count} breaches! DO NOT USE IT."
    
    return "✅ This password has not been found in known breaches."

# GUI Interface
def evaluate_password():
    """Handles password checking and updates the GUI."""
    password = entry.get()
    
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    # Check password strength
    strength, feedback = check_password_strength(password)
    result_label.config(text=f"Strength: {strength}")

    # Display feedback
    feedback_text.set("\n".join(feedback) if feedback else "✅ Looks good!")

    # Check for breaches
    breach_status = check_pwned_password(password)
    breach_label.config(text=breach_status)

# Tkinter GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x350")
root.resizable(False, False)

# Title Label
title_label = tk.Label(root, text="🔐 Password Strength Checker", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Entry for Password
entry = tk.Entry(root, width=30, show="*")
entry.pack(pady=5)

# Button to Check Password
check_button = tk.Button(root, text="Check Password", command=evaluate_password)
check_button.pack(pady=5)

# Result Label
result_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
result_label.pack(pady=5)

# Feedback Label
feedback_text = tk.StringVar()
feedback_label = tk.Label(root, textvariable=feedback_text, justify="left", fg="red")
feedback_label.pack(pady=5)

# Breach Label
breach_label = tk.Label(root, text="", fg="white")
breach_label.pack(pady=10)

# Run the GUI
root.mainloop()
