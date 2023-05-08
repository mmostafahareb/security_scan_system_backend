import os
import json
import subprocess
from .models import *
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import requests
from keras.models import load_model
from keras.preprocessing.text import Tokenizer
from keras.utils.data_utils import pad_sequences

model_path = os.path.join(os.path.dirname(__file__), 'my_model.h5')
model = load_model(model_path)
def scan_dockerfile(directory, scan_id):
    scans = Scans(scan_id=scan_id)
    dockerfile_path = None
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == "Dockerfile":
                dockerfile_path = os.path.join(root, file)
                break
        if dockerfile_path:
            break

    if not dockerfile_path:
        return []

    subprocess.run(["docker", "build", "-t", "temp-image", "-f", dockerfile_path, "."], check=True)

    output = subprocess.check_output(["docker", "scan", "--json", "temp-image"])

    vulnerabilities = []
    json_output = json.loads(output)
    for item in json_output.get("data", {}).get("vulnerabilities", []):
        vulnerability = Vulnerabilities(
            type="docker_vulnerability",
            file_location=dockerfile_path,
            line_of_code="",
            severity=item.get("severity", ""),
            cve_id=item.get("cve_id", ""),
            description=item.get("description", ""),
            suggested_fix=item.get("fixed_by", "")
        )
        vulnerabilities.append(vulnerability)
    scans.vulnerabilities.add(*vulnerabilities)
    scans.save()

def scan_code(directory, scan_id):
    scans = Scans(scan_id=scan_id)
    try:
        for language in ["cpp", "java", "ruby", "javascript", "python"]:
            try:
                subprocess.check_output(["codeql", "database", "create", f"--language={language}", "--no-joins", "database", directory], stderr=subprocess.STDOUT)
                subprocess.check_output(["codeql", "database", "analyze", "--format=sarif-latest", "--output=result.sarif", "database"], stderr=subprocess.STDOUT)

                with open("result.sarif") as f:
                    sarif_data = json.load(f)

                vulnerabilities = []
                for run in sarif_data.get("runs", []):
                    for result in run.get("results", []):
                        vulnerability = Vulnerabilities(
                            type="sc_analysis",
                            file_location=result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                            line_of_code=result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", ""),
                            severity=result.get("level", ""),
                            cve_id=result.get("ruleId", ""),
                            description=result.get("message", {}).get("text", ""),
                            suggested_fix=result.get("message", {}).get("text", "")
                        )
                        vulnerabilities.append(vulnerability)

                scans.vulnerabilities.add(*vulnerabilities)

            except subprocess.CalledProcessError as e:
                print(f"Error while scanning {language}: {e.output}")
                continue

    finally:
        subprocess.check_output(["codeql", "database", "remove", "database"], stderr=subprocess.STDOUT)

    scans.save()
def parse_requirements(file_path):
    # Read the requirements.txt file
    with open(file_path, "r") as file:
        file_data = file.read()

    # Split the file data into lines and remove any empty lines
    lines = [line.strip() for line in file_data.split('\n') if line.strip() != '']

    # Map over each line and extract the package name and version
    package_list = [f"pypi:{name}:{version}" for line in lines for name, version in [line.split('==')]]

    # Print the list of packages to the console
    return package_list


def parse_gradle_build(file_path):
    # Read the build.gradle file
    with open(file_path, "r") as file:
        file_data = file.read()

    # Extract the dependency information from the file data
    regex = r"(?:implementation|compile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
    dependency_list = []

    for match in re.finditer(regex, file_data):
        name = match.group(1)
        version = match.group(3)
        dependency_list.append(f"gradle:{name}:{version}")

    # Print the list of dependencies to the console
    return dependency_list

def parse_pipfile_lock(file_path):
    # Read the Pipfile.lock file
    with open(file_path, "r") as file:
        file_data = file.read()

    # Parse the JSON data
    json_data = json.loads(file_data)

    # Extract the package information from the parsed data
    packages = json_data["default"]

    # Map over each package and extract the name and version
    package_list = [f"pypi:{pkg_name}:{packages[pkg_name]['version']}" for pkg_name in packages]

    # Print the list of packages to the console
    return package_list

def parse_pom_xml(file_path):
    # Read the pom.xml file
    with open(file_path, "r") as file:
        xml_data = file.read()

    # Parse the XML data using ElementTree
    root = ET.fromstring(xml_data)

    # Define the XML namespace for Maven POM files
    ns = {'mvn': 'http://maven.apache.org/POM/4.0.0'}

    # Extract the dependency information from the parsed data
    dependencies = root.find('mvn:dependencies', ns)
    dependency_list = []

    if dependencies is not None:
        for dep in dependencies.findall('mvn:dependency', ns):
            name = dep.find('mvn:artifactId', ns).text
            version = dep.find('mvn:version', ns).text
            dependency_list.append(f"maven:{name}:{version}")

    return dependency_list

def parse_package_lock(file_path):
    # Read the package-lock.json file
    with open(file_path, "r") as file:
        file_data = file.read()

    # Parse the JSON data
    json_data = json.loads(file_data)

    # Extract the package information from the parsed data
    packages = json_data["dependencies"]

    # Map over each package and extract the name and version
    package_list = [f"npm:{pkg_name}:{packages[pkg_name]['version']}" for pkg_name in packages]

    return package_list
def scan_credentials(directory, project_id):
    # Define a regular expression to match hardcoded credentials
    credential_regex = re.compile(r'(password|key|token|secret)\s*=\s*[\'\"]\S+[\'\"]')
    tokenizer = Tokenizer()
    for subdir, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(subdir, file)
            with open(filepath, 'r') as f:
                text = f.read()
            tokens = tokenizer.tokenize(text)
            sequence = tokenizer.texts_to_sequences([tokens])
            sequence_padded = pad_sequences(sequence, maxlen=1200)
            prediction = model.predict(sequence_padded)
            if prediction > 0.5:
                # Add an entry to the Hardcoded_Creds model
                for i, line in enumerate(text.split('\n')):
                    match = credential_regex.search(line)
                    if match:
                        cred = Hardcoded_Creds(file_location=filepath, line_of_code=i+1)
                        cred.save()
                # Update the Scans model
                scan = Scans.objects.get(project_id=project_id)
                scan.hardcoded_creds.add(cred)

def get_third_parties(directory, scan_id):
    scans = Scans.objects.get(scan_id=scan_id)

    # Mapping of file extensions to parsing functions
    parsing_functions = {
        "pipfile.lock": parse_pipfile_lock,
        "pom.xml": parse_pom_xml,
        "requirements.txt": parse_requirements,
        "build.gradle": parse_gradle_build,
        "package-lock.json": parse_package_lock,
    }

    dependencies = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1][1:].lower()
            if file_extension in parsing_functions:
                parser_function = parsing_functions[file_extension]
                file_dependencies = parser_function(file_path)
                dependencies += file_dependencies

    # Create BOM objects and add them to the scan
    bom_objects = []
    for dep in dependencies:
        repo, dependency, version = dep.split(":")
        bom_object, created = Bom.objects.get_or_create(source=repo, artifact=dependency, version=version)
        bom_objects.append(bom_object)
    scans.bom.set(bom_objects)

    scans.save()
    return dependencies
OSV_API_URL = "https://api.osv.dev/v1/search/bulk"

def scan_third_parties(directory, scan_id):
    # Scan the project and get the list of dependencies
    dependencies = get_third_parties(directory, scan_id)

    # Prepare the OSV API request payload
    osv_query_objects = []
    for dep in dependencies:
        repo, dependency, version = dep.split(":")
        osv_query_object = {"affects": [{"name": dependency, "version": version, "ecosystem": repo}]}
        osv_query_objects.append(osv_query_object)
    osv_payload = {"queries": osv_query_objects}

    # Send the request to the OSV API
    osv_response = requests.post(OSV_API_URL, json=osv_payload).json()

    # Update the scans object with vulnerabilities and BOM objects
    scans = Scans.objects.get(scan_id=scan_id)
    bom_objects = []
    vulnerability_objects = []
    for index, query_result in enumerate(osv_response):
        vulnerabilities = query_result.get("vulnerabilities", [])
        for vulnerability in vulnerabilities:
            cve_id = vulnerability.get("id")
            description = vulnerability.get("description")
            suggested_fix = vulnerability.get("fix", {}).get("diff")
            severity = vulnerability.get("cvssScore", {}).get("severity")
            for affected_package in vulnerability.get("affected", []):
                package_name = affected_package.get("name")
                package_version = affected_package.get("version")
                package_ecosystem = affected_package.get("ecosystem")
                bom_object, created = Bom.objects.get_or_create(source=package_ecosystem, artifact=package_name, version=package_version)
                bom_objects.append(bom_object)
                vulnerability_object = Vulnerabilities.objects.create(
                    type="OSV",
                    file_location="",
                    line_of_code="",
                    severity=severity,
                    cve_id=cve_id,
                    description=description,
                    suggested_fix=suggested_fix
                )
                vulnerability_object.bom.add(bom_object)
                vulnerability_objects.append(vulnerability_object)
    scans.bom.set(bom_objects)
    scans.vulnerabilities.set(vulnerability_objects)
    scans.save()
def scan_project(scan_id,directory):
    scan_credentials(directory,scan_id)
    scan_third_parties(directory, scan_id)
    scan_dockerfile(directory, scan_id)
    scan_code(directory, scan_id)