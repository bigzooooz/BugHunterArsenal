import requests
import re
import time

VALIDATION_TIMEOUT = 5

def validate_api_key(provider, key_value):
    provider_lower = provider.lower()
    
    if "mws" in provider_lower and "amazon" in provider_lower:
        return validate_amazon_mws(key_value)
    elif "aws" in provider_lower or "amazon" in provider_lower:
        return validate_aws(key_value)
    elif "github" in provider_lower:
        return validate_github(key_value)
    elif "slack" in provider_lower:
        if "webhook" in provider_lower:
            return validate_slack_webhook(key_value)
        else:
            return validate_slack_token(key_value)
    elif "stripe" in provider_lower:
        return validate_stripe(key_value)
    elif "twilio" in provider_lower:
        return validate_twilio(key_value)
    elif "telegram" in provider_lower:
        return validate_telegram(key_value)
    elif "gitlab" in provider_lower and ("ci" in provider_lower or "cd" in provider_lower):
        return validate_gitlab_cicd(key_value)
    elif "gitlab" in provider_lower:
        return validate_gitlab(key_value)
    elif "npm" in provider_lower:
        return validate_npm(key_value)
    elif "sendgrid" in provider_lower:
        return validate_sendgrid(key_value)
    elif "openai" in provider_lower:
        return validate_openai(key_value)
    elif "discord" in provider_lower and "webhook" in provider_lower:
        return validate_discord_webhook(key_value)
    elif "heroku" in provider_lower:
        return validate_heroku(key_value)
    elif "firebase" in provider_lower:
        return validate_firebase(key_value)
    elif "mailgun" in provider_lower:
        return validate_mailgun(key_value)
    elif "mapbox" in provider_lower:
        return validate_mapbox(key_value)
    elif "dropbox" in provider_lower:
        return validate_dropbox(key_value)
    elif "postman" in provider_lower:
        return validate_postman(key_value)
    elif "cloudinary" in provider_lower:
        return validate_cloudinary(key_value)
    elif "facebook" in provider_lower:
        return validate_facebook(key_value)
    elif "mailchimp" in provider_lower:
        return validate_mailchimp(key_value)
    elif "square" in provider_lower:
        return validate_square(key_value)
    elif "paypal" in provider_lower or "braintree" in provider_lower:
        return validate_paypal_braintree(key_value)
    elif "picatic" in provider_lower:
        return validate_picatic(key_value)
    elif "alibaba" in provider_lower:
        return validate_alibaba(key_value)
    elif "grafana" in provider_lower:
        if "service account" in provider_lower or "glsa_" in key_value.lower():
            return validate_grafana_service_account(key_value)
        else:
            return validate_grafana(key_value)
    elif "instagram" in provider_lower:
        return validate_instagram(key_value)
    elif "azure" in provider_lower or "microsoft" in provider_lower:
        return validate_azure(key_value)
    elif "vercel" in provider_lower:
        return validate_vercel(key_value)
    elif "shopify" in provider_lower:
        return validate_shopify(key_value)
    elif "oauth" in provider_lower and "bearer" in provider_lower:
        return validate_oauth2_bearer(key_value)
    else:
        return "manual"

def validate_aws(key):
    try:
        url = "https://iam.amazonaws.com/"
        headers = {
            "Authorization": f"AWS4-HMAC-SHA256 Credential={key}/20240101/us-east-1/iam/aws4_request"
        }
        response = requests.get(url, headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 403:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_github(key):
    try:
        headers = {"Authorization": f"token {key}"}
        response = requests.get("https://api.github.com/user", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_slack_token(key):
    try:
        response = requests.post(
            f"https://slack.com/api/auth.test?token={key}&pretty=1",
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("ok") is True:
                return "valid"
            elif data.get("ok") is False:
                return "invalid"
    except:
        pass
    return "manual"

def validate_slack_webhook(url):
    try:
        response = requests.post(url, json={"text": "test"}, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 404:
            return "invalid"
    except:
        pass
    return "manual"

def validate_stripe(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.stripe.com/v1/charges?limit=1", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_twilio(key):
    try:
        account_sid = key[:34] if len(key) >= 34 else key
        response = requests.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
            auth=(account_sid, key),
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_telegram(key):
    try:
        bot_id = key.split(":")[0] if ":" in key else None
        if bot_id:
            response = requests.get(
                f"https://api.telegram.org/bot{key}/getMe",
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("ok") is True:
                    return "valid"
                elif data.get("ok") is False:
                    return "invalid"
    except:
        pass
    return "manual"

def validate_gitlab(key):
    try:
        headers = {"PRIVATE-TOKEN": key}
        response = requests.get("https://gitlab.com/api/v4/user", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_npm(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://registry.npmjs.org/-/npm/v1/user", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_sendgrid(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.sendgrid.com/v3/user/profile", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_openai(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.openai.com/v1/models", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_discord_webhook(url):
    try:
        response = requests.post(url, json={"content": "test"}, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 204 or response.status_code == 200:
            return "valid"
        elif response.status_code == 404:
            return "invalid"
    except:
        pass
    return "manual"

def validate_heroku(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.heroku.com/account", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_firebase(key):
    return "manual"

def validate_mailgun(key):
    try:
        domain = "example.com"
        response = requests.get(
            f"https://api.mailgun.net/v3/domains/{domain}",
            auth=("api", key),
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_mapbox(key):
    try:
        response = requests.get(
            f"https://api.mapbox.com/geocoding/v5/mapbox.places/test.json?access_token={key}",
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_dropbox(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.post("https://api.dropboxapi.com/2/users/get_current_account", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_postman(key):
    try:
        headers = {"X-Api-Key": key}
        response = requests.get("https://api.getpostman.com/me", headers=headers, timeout=VALIDATION_TIMEOUT, verify=False)
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_cloudinary(key):
    try:
        if key.startswith("cloudinary://"):
            cloud_name = key.split("://")[1].split(":")[0] if "://" in key else None
            if cloud_name:
                response = requests.get(
                    f"https://res.cloudinary.com/{cloud_name}/image/upload/v1/test",
                    timeout=VALIDATION_TIMEOUT,
                    verify=False
                )
                if response.status_code != 404:
                    return "valid"
    except:
        pass
    return "manual"

def validate_facebook(key):
    try:
        response = requests.get(
            f"https://graph.facebook.com/me?access_token={key}",
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            if "id" in data:
                return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_mailchimp(key):
    try:
        dc = key.split("-")[-1] if "-" in key else "us1"
        response = requests.get(
            f"https://{dc}.api.mailchimp.com/3.0/",
            auth=("anystring", key),
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_square(key):
    try:
        if key.startswith("sq0atp-"):
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(
                "https://connect.squareup.com/v2/locations",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_paypal_braintree(key):
    try:
        if "$" in key:
            parts = key.split("$")
            if len(parts) >= 4:
                environment = parts[1]
                merchant_id = parts[2]
                public_key = parts[3]
                url = f"https://api.{environment}.braintreegateway.com/merchants/{merchant_id}/client_token"
                response = requests.post(
                    url,
                    auth=(public_key, key),
                    timeout=VALIDATION_TIMEOUT,
                    verify=False
                )
                if response.status_code == 201:
                    return "valid"
                elif response.status_code == 401:
                    return "invalid"
    except:
        pass
    return "manual"

def validate_picatic(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get(
            "https://picatic.com/api/v2/events",
            headers=headers,
            timeout=VALIDATION_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            return "valid"
        elif response.status_code == 401:
            return "invalid"
    except:
        pass
    return "manual"

def validate_alibaba(key):
    try:
        if key.startswith("LTAI"):
            response = requests.get(
                "https://ecs.aliyuncs.com/?Action=DescribeRegions&Format=JSON",
                headers={"Authorization": f"Bearer {key}"},
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401 or response.status_code == 403:
                return "invalid"
    except:
        pass
    return "manual"

def validate_grafana(key):
    try:
        if key.startswith("eyJrIjoi"):
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(
                "http://localhost:3000/api/auth/keys",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_grafana_service_account(key):
    try:
        if key.startswith("glsa_"):
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(
                "http://localhost:3000/api/serviceaccounts",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_instagram(key):
    try:
        if key.startswith("IG"):
            response = requests.get(
                f"https://graph.instagram.com/me?access_token={key}",
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                data = response.json()
                if "id" in data:
                    return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_azure(key):
    try:
        if "azure" in key.lower():
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(
                "https://management.azure.com/subscriptions?api-version=2020-01-01",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_vercel(key):
    try:
        if key.startswith("vercel_"):
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(
                "https://api.vercel.com/v2/user",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_shopify(key):
    try:
        if len(key) == 32 and all(c in "0123456789abcdef" for c in key.lower()):
            headers = {"X-Shopify-Access-Token": key}
            response = requests.get(
                "https://test.myshopify.com/admin/api/2023-10/shop.json",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_amazon_mws(key):
    try:
        if key.startswith("amzn.mws."):
            response = requests.get(
                "https://mws.amazonservices.com/",
                headers={"Authorization": f"AWS {key}"},
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"

def validate_oauth2_bearer(key):
    try:
        if key.startswith("Bearer "):
            token = key.replace("Bearer ", "")
            if "." in token:
                parts = token.split(".")
                if len(parts) >= 2:
                    return "manual"
    except:
        pass
    return "manual"

def validate_gitlab_cicd(key):
    try:
        if key.startswith("glcbt-"):
            headers = {"JOB-TOKEN": key}
            response = requests.get(
                "https://gitlab.com/api/v4/user",
                headers=headers,
                timeout=VALIDATION_TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return "valid"
            elif response.status_code == 401:
                return "invalid"
    except:
        pass
    return "manual"
