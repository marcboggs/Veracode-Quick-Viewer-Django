from django.shortcuts import render, get_object_or_404 # Though not strictly needed for current functions
from django.http import Http404, HttpResponse, HttpResponseServerError
from .services import veracode_api
from .utils import xml_parser, report_utils
import logging
import csv # For CSV export
import xml.etree.ElementTree as ET # For report_detail app_id parsing

logger = logging.getLogger(__name__)

def application_list(request):
    """
    View to list all Veracode applications.
    """
    context = {'applications': [], 'error': None}
    try:
        applications_data = veracode_api.get_applications()
        if isinstance(applications_data, dict) and 'error' in applications_data:
            context['error'] = applications_data['error']
            logger.error(f"API Error in application_list: {applications_data['error']}")
        else:
            # Ensure applications_data is a list before passing to template
            if isinstance(applications_data, list):
                context['applications'] = applications_data
            else:
                context['error'] = "Received unexpected data format for applications."
                logger.error(f"Unexpected data format in application_list: {type(applications_data)}")

    except Exception as e:
        logger.exception("Exception in application_list view")
        context['error'] = f"An unexpected error occurred: {str(e)}"

    return render(request, 'reporter/application_list.html', context)

def build_list(request, app_id):
    """
    View to list all builds for a given Veracode application ID.
    """
    context = {'builds': [], 'app_id': app_id, 'app_name': None, 'error': None}

    # Try to get app_name (optional, for better UX)
    # This is inefficient if get_applications() makes an API call every time.
    # A better approach would be a get_application_details(app_id) or caching.
    try:
        apps_data = veracode_api.get_applications()
        if isinstance(apps_data, list):
            current_app = next((app for app in apps_data if app.get('id') == app_id), None)
            if current_app and 'profile' in current_app and 'name' in current_app['profile']:
                context['app_name'] = current_app['profile']['name']
        elif isinstance(apps_data, dict) and 'error' in apps_data:
             # Log this error but don't necessarily block build listing
            logger.warning(f"API Error when fetching app name for build_list (app_id: {app_id}): {apps_data['error']}")

    except Exception as e:
        logger.warning(f"Could not fetch app name for build_list (app_id: {app_id}): {e}")

    try:
        builds_data = veracode_api.get_build_list(app_id)
        if isinstance(builds_data, dict) and 'error' in builds_data:
            context['error'] = builds_data['error']
            logger.error(f"API Error in build_list (app_id: {app_id}): {builds_data['error']}")
        else:
             # Ensure builds_data is a list before passing to template
            if isinstance(builds_data, list):
                context['builds'] = builds_data
            else:
                context['error'] = "Received unexpected data format for builds."
                logger.error(f"Unexpected data format in build_list (app_id: {app_id}): {type(builds_data)}")

    except Exception as e:
        logger.exception(f"Exception in build_list view (app_id: {app_id})")
        # If there was an error fetching app_name, we might overwrite it here.
        # Prioritize build list errors if both occur.
        context['error'] = f"An unexpected error occurred while fetching builds: {str(e)}"

    if not context['app_name'] and not context['error']: # If app_name fetch failed silently
        context['app_name'] = f"App ID {app_id}"


    return render(request, 'reporter/build_list.html', context)

def report_detail(request, build_id):
    context = {
        'build_id': build_id,
        'app_id': None, # Will try to populate this
        'app_name': None,
        'build_version': None,
        'flaws': [],
        'sca_components': [],
        'summary_data': {},
        'compliance_data': {},
        'raw_xml': None,
        'severity_filter': request.GET.get('severity_filter', ''),
        'cwe_filter': request.GET.get('cwe_filter', ''),
        'error': None
    }

    try:
        raw_xml = veracode_api.get_detailed_report(build_id)
        if isinstance(raw_xml, dict) and 'error' in raw_xml:
            context['error'] = raw_xml['error']
            logger.error(f"API Error in report_detail (build_id: {build_id}): {raw_xml['error']}")
            return render(request, 'reporter/report_detail.html', context)

        if not raw_xml: # Should be caught by error dict check, but as a safeguard
            context['error'] = "No report XML content received from API."
            logger.error(f"No XML content for build_id: {build_id}")
            return render(request, 'reporter/report_detail.html', context)

        context['raw_xml'] = raw_xml

        flaws, sca_components = xml_parser.parse_detailed_report_xml(raw_xml)
        context['flaws_original'] = flaws # Keep original for summary/compliance
        context['sca_components'] = sca_components

        context['summary_data'] = report_utils.generate_summary_data(flaws, sca_components)
        context['compliance_data'] = report_utils.generate_compliance_data(flaws, raw_xml)

        # Filtering
        filtered_flaws = list(flaws) # Make a copy to filter
        if context['severity_filter']:
            filtered_flaws = [f for f in filtered_flaws if f.get('Severity') == context['severity_filter']]
        if context['cwe_filter']:
            filtered_flaws = [f for f in filtered_flaws if context['cwe_filter'] in f.get('CWE', '')]
        context['flaws'] = filtered_flaws

        # Attempt to get app_id, app_name, build_version for context (inefficiently)
        # This part is best-effort and should not block the report if it fails
        try:
            # Find app_id from the report XML itself if possible (more reliable than iterating all apps)
            # This depends on attributes in the detailed report XML
            root = ET.fromstring(raw_xml.encode('utf-8'))
            context['app_id'] = root.get('app_id')
            context['app_name'] = root.get('app_name', f"App ID {context['app_id']}")
            context['build_version'] = root.get('version', f"Build ID {build_id}")

            # If app_id is still None, try the less efficient way (only if necessary)
            if not context['app_id']:
                logger.warning(f"Could not determine app_id directly from XML for build {build_id}. Attempting scan of all applications.")
                all_applications = veracode_api.get_applications()
                if isinstance(all_applications, list):
                    for app_data in all_applications:
                        if 'id' in app_data:
                            builds_for_app = veracode_api.get_build_list(app_data['id'])
                            if isinstance(builds_for_app, list):
                                for build_data in builds_for_app:
                                    if build_data.get('build_id') == build_id:
                                        context['app_id'] = app_data['id']
                                        context['app_name'] = app_data.get('profile', {}).get('name', f"App ID {app_data['id']}")
                                        context['build_version'] = build_data.get('version', f"Build ID {build_id}")
                                        break
                            if context['app_id']: break

            if not context['app_name']: context['app_name'] = f"App ID {context['app_id'] or 'Unknown'}"
            if not context['build_version']: context['build_version'] = f"Build ID {build_id}"

        except Exception as e:
            logger.warning(f"Could not determine app/build metadata for report_detail (build_id: {build_id}): {e}")
            if not context['app_name']: context['app_name'] = "Unknown Application"
            if not context['build_version']: context['build_version'] = f"Build ID {build_id}"


    except Exception as e:
        logger.exception(f"Exception in report_detail view (build_id: {build_id})")
        context['error'] = f"An critical error occurred: {str(e)}"

    return render(request, 'reporter/report_detail.html', context)

def export_static_findings_csv(request, build_id):
    try:
        raw_xml = veracode_api.get_detailed_report(build_id)
        if isinstance(raw_xml, dict) and 'error' in raw_xml:
            logger.error(f"API Error in export_static_findings_csv (build_id: {build_id}): {raw_xml['error']}")
            return HttpResponseServerError(f"Could not fetch report data from Veracode API: {raw_xml['error']}")

        if not raw_xml:
            logger.error(f"No XML content for export_static_findings_csv, build_id: {build_id}")
            return HttpResponseServerError("No report XML content received from Veracode API.")

        flaws, _ = xml_parser.parse_detailed_report_xml(raw_xml)
        if flaws is None: # parse_detailed_report_xml returns ([],[]) on error, so this check might be redundant
            logger.error(f"Error parsing XML for export_static_findings_csv, build_id: {build_id}")
            return HttpResponseServerError("Error parsing the Veracode report XML.")

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="static_findings_{build_id}.csv"'

        writer = csv.writer(response)
        header = ["ID", "Severity", "CWE", "Category", "File", "Line", "Function", "Status", "Module", "Grace Period Expires"]
        writer.writerow(header)

        for flaw in flaws:
            writer.writerow([
                flaw.get("ID", ""),
                flaw.get("Severity", ""),
                flaw.get("CWE", ""),
                flaw.get("Category", ""),
                flaw.get("File", ""),
                flaw.get("Line", ""),
                flaw.get("Function", ""),
                flaw.get("Status", ""),
                flaw.get("Module", ""),
                flaw.get("grace_period_expires", "") # Matches the key from xml_parser
            ])

        return response

    except Exception as e:
        logger.exception(f"Exception in export_static_findings_csv (build_id: {build_id})")
        return HttpResponseServerError(f"An unexpected error occurred during CSV export: {str(e)}")


def export_sca_findings_csv(request, build_id):
    try:
        raw_xml = veracode_api.get_detailed_report(build_id)
        if isinstance(raw_xml, dict) and 'error' in raw_xml:
            logger.error(f"API Error in export_sca_findings_csv (build_id: {build_id}): {raw_xml['error']}")
            return HttpResponseServerError(f"Could not fetch report data from Veracode API: {raw_xml['error']}")

        if not raw_xml:
            logger.error(f"No XML content for export_sca_findings_csv, build_id: {build_id}")
            return HttpResponseServerError("No report XML content received from Veracode API.")

        _, sca_components = xml_parser.parse_detailed_report_xml(raw_xml)
        if sca_components is None: # parse_detailed_report_xml returns ([],[]) on error
            logger.error(f"Error parsing XML for export_sca_findings_csv, build_id: {build_id}")
            return HttpResponseServerError("Error parsing the Veracode report XML for SCA components.")

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="sca_findings_{build_id}.csv"'

        writer = csv.writer(response)
        # Based on report-gpt.py and common SCA fields
        header = ["Component", "Version", "Vendor", "Description", "CPE", "Licenses", "Vulnerabilities (CVE - Severity)"]
        writer.writerow(header)

        for comp in sca_components:
            licenses_str = "; ".join([lic.get('name', '') for lic in comp.get('Licenses', [])])
            vulns_str = "; ".join([f"{v.get('cveid','')} ({v.get('severity','')})" for v in comp.get('Vulnerabilities', [])])
            writer.writerow([
                comp.get("Component", ""),
                comp.get("Version", ""),
                comp.get("Vendor", ""),
                comp.get("Description", ""),
                comp.get("CPE", ""),
                licenses_str,
                vulns_str
            ])

        return response

    except Exception as e:
        logger.exception(f"Exception in export_sca_findings_csv (build_id: {build_id})")
        return HttpResponseServerError(f"An unexpected error occurred during CSV export: {str(e)}")
