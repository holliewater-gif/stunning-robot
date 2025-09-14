$users=@("crewtravelco28@theapollogroup.com","valid.user@company.onmicrosoft.com","invalid.user@company.com","valid.user_gmail.com#EXT#@company.onmicrosoft.com")

# Loop trough all users
foreach($user in $users)
{
    $exists = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -ContentType "application/json" -Method POST -Body (@{"username"="$user"; "isOtherIdpSupported" =  $true}|ConvertTo-Json) | Select -ExpandProperty IfExistsResult
    $properties = [ordered]@{"Username"=$user; "Exists"=$($exists -eq 0 -or $exists -eq 6)}
    New-Object -TypeName PSObject -Property $properties
}
import requests
import json
#ernie.philp@ahlstrom-munksjo.com
user ="info@esentire.com"
url = "https://login.microsoftonline.com/common/GetCredentialType"
payload = {
        "username": user,
        "isOtherIdpSupported": True
    }

try:
    response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", json=payload)
    if response.status_code == 200:
        json_response = response.json()
        user_branding = response.json()['EstsProperties'].get('UserTenantBranding', [])
        if user_branding:
            banner_logo = user_branding[0].get('BannerLogo', 'No BannerLogo field found')
            print(f"BannerLogo: {banner_logo}")
        else:
            print("no banner")
        print(f"Session Status: {response.json().get('IfExistsResult')}")
    else:
        print(f"Request failed for user '{user}'. Status code: {response.status_code}")
except Exception as e:
    print(f"Error occurred for user '{user}': {e}")


    //*[@id="idA_SAASTO_Resend"]