import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

API_BASE = "https://api.veracode.com"
LEGACY_API_BASE = "https://analysiscenter.veracode.com/api/5.0"

# Namespace for Veracode buildlist XML
BL_NS = {'bl': 'https://analysiscenter.veracode.com/schema/2.0/buildlist'}

def get_veracode_hmac_auth():
    """
    Retrieves Veracode API key and secret from Django settings
    and returns a RequestsAuthPluginVeracodeHMAC instance.
    Raises ImproperlyConfigured if keys are not set.
    """
    api_key = getattr(settings, 'VERACODE_API_KEY', None)
    api_secret = getattr(settings, 'VERACODE_API_SECRET', None)

    if not api_key or not api_secret:
        raise ImproperlyConfigured(
            "VERACODE_API_KEY and VERACODE_API_SECRET must be set in Django settings."
            "It is recommended to set these via environment variables."
        )
    return RequestsAuthPluginVeracodeHMAC()

def get_applications():
    """
    Fetches the list of applications from the Veracode API.
    Returns a list of application dictionaries.
    """
    try:
        auth = get_veracode_hmac_auth()
        response = requests.get(
            f"{API_BASE}/appsec/v1/applications?size=1000",  # Consider pagination for >1000 apps
            auth=auth,
            headers={"Accept": "application/json"}
        )
        response.raise_for_status()  # Raises HTTPError for bad responses (4XX or 5XX)
        return response.json().get("_embedded", {}).get("applications", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Veracode applications: {e}")
        # Optionally, re-raise as a custom exception or return an error indicator
        return {"error": str(e)}
    except ImproperlyConfigured:
        raise # Re-raise if API keys are not configured
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_applications: {e}")
        return {"error": f"An unexpected error occurred: {str(e)}"}


def get_build_list(app_id):
    """
    Fetches the list of builds for a given application ID from the Veracode Legacy API.
    Returns a list of build dictionaries.
    """
    try:
        auth = get_veracode_hmac_auth()
        response = requests.get(
            f"{LEGACY_API_BASE}/getbuildlist.do?app_id={app_id}",
            auth=auth
        )
        response.raise_for_status()

        # Check if response is empty or not valid XML
        if not response.content:
            logger.warning(f"Received empty build list for app_id {app_id}")
            return []

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as e:
            logger.error(f"Error parsing XML for app_id {app_id}: {e}. Response content: {response.content[:500]}")
            return {"error": f"Error parsing XML: {e}"}

        builds = []
        for b_element in root.findall("bl:build", BL_NS):
            builds.append({
                'version': b_element.get('version'),
                'build_id': b_element.get('build_id'),
                'policy_updated_date': b_element.get('policy_updated_date')
            })
        return builds
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Veracode build list for app_id {app_id}: {e}")
        return {"error": str(e)}
    except ImproperlyConfigured:
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_build_list for app_id {app_id}: {e}")
        return {"error": f"An unexpected error occurred: {str(e)}"}


def get_detailed_report(build_id):
    """
    Fetches the detailed report (XML) for a given build ID from the Veracode Legacy API.
    Returns the raw XML content as a string.
    """
    try:
        auth = get_veracode_hmac_auth()
        response = requests.get(
            f"{LEGACY_API_BASE}/detailedreport.do?build_id={build_id}",
            auth=auth
        )
        response.raise_for_status()
        return response.content.decode("utf-8")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Veracode detailed report for build_id {build_id}: {e}")
        return {"error": str(e)} # Return error as dict to be consistent, or handle differently
    except ImproperlyConfigured:
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_detailed_report for build_id {build_id}: {e}")
        return {"error": f"An unexpected error occurred: {str(e)}"}
