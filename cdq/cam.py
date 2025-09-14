import requests,json
payload = {"username": "info@esentire.com","isOtherIdpSupported": True}
banner=""
try:
    response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", json=payload)
    if response.status_code == 200:
            try:
                banner+=f"{response.json().get('IfExistsResult', 'null')}:"
            except:
                banner+="null:"
            try:
                banner+=f"{response.json()['EstsProperties'].get('UserTenantBranding', [])[0].get('BannerLogo', 'null')}:"
            except:
                banner+="null:"
            try:
                banner+=f"{response.json()['EstsProperties'].get('UserTenantBranding', [])[0].get('Illustration', 'null')}:"
            except:
                banner+="null:"
            try:
                banner+=f"{response.json()['EstsProperties'].get('UserTenantBranding', [])[0].get('BackgroundColor', 'null')}"
            except:
                banner+="null"
            print(banner)
    else:
        print(f"Request failed for user 'info@esentire.com'. Status code: {response.status_code}")
except Exception as e:
    print(f"Error occurred for user 'info@esentire.com': {e}")