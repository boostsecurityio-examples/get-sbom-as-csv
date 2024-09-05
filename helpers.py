import os
import json
import datetime
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport


timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M")
artifacts_folder = "artifacts"
timestamp_folder = os.path.join(artifacts_folder, timestamp)


def create_artifacts_folder():
    if not os.path.exists(artifacts_folder):
        os.makedirs(artifacts_folder)
        print(f"Created folder: {artifacts_folder}")
    else:
        print(f"Folder already exists: {artifacts_folder}")


def create_timestamp_folder():
    if not os.path.exists(timestamp_folder):
        os.makedirs(timestamp_folder)
        print(f"Created folder: {timestamp_folder}")
    else:
        print(f"Folder already exists: {timestamp_folder}")


def get_client():
    token_string = os.getenv("BOOST_API_TOKEN") or ""
    if token_string == "":
        raise ValueError(
            "Please provide a token by setting the BOOST_API_TOKEN environment variable"
        )

    token = f"ApiKey {token_string}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Prefer": "safe",
        "Content-Type": "application/json",
        "Authorization": token,
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-GPC": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }
    transport = AIOHTTPTransport(
        url="https://api.boostsecurity.io/sbom-inventory/graphql", headers=headers
    )

    return Client(transport=transport, fetch_schema_from_transport=True)


def get_sbom(options):
    analysis_id = options.get("analysis_id")
    client = options.get("client")
    if analysis_id == "" or analysis_id == None:
        raise ValueError("Analysis ID is required")

    query = gql(
        """

    query (
        $first: Int
        $after: String
        $last: Int
        $before: String
        $page: Int
        $search: String
        $orgName: String
        $projectName: String
        $labelName: String
        $withVulnerabilities: Boolean
        $packageTypes: [String!]
        $isFixable: Boolean
        $withoutTransitiveThrough: Boolean
        $analysisId: String
        $orderBy: [PackagesOrder!]
        $locatePackageId: String
        $licenses: [String!]
    ) {
        packages(
            first: $first
            after: $after
            last: $last
            before: $before
            page: $page
            filters: {
                search: $search
                asset: {
                    organizationName: $orgName
                    projectName: $projectName
                    assetLabel: $labelName
                }
                analysisId: $analysisId
                withVulnerabilities: $withVulnerabilities
                packageTypes: $packageTypes
                isFixable: $isFixable
                withoutTransitiveThrough: $withoutTransitiveThrough
                licenses: $licenses
            }
            orderBy: $orderBy
            locatePackageId: $locatePackageId
        ) {
            totalCount
            edges {
                node {
                    packageId
                    name
                    version
                    packageType
                    ecosystem
                    analysisCount
                    vulnerabilities {
                        edges {
                            node {
                                originalId
                                fixedBy
                                severity
                            }
                        }
                    }
                    vulnerabilityCount {
                        critical
                        high
                        medium
                        low
                        info
                        none
                        unknown
                    }
                    analysisCount
                    transitiveThrough {
                        name
                        version
                    }
                    licenses {
                        expression
                    }
                    scorecard {
                        date
                        checks {
                            name
                            score
                            documentationDesc
                            documentationUrl
                            reason
                            details
                        }
                        overallScore
                    }
                    scorecardUrl
                }
                cursor
            }
            filters {
                packageTypes {
                    value
                }
                licenses {
                    value
                }
            }
            pageInfo {
                hasNextPage
                hasPreviousPage
                startCursor
                endCursor
            }
        }
    }

    """
    )
    params = {
        "first": 100,
        "search": "",
        "withVulnerabilities": False,
        "isFixable": False,
        "withoutTransitiveThrough": False,
        "licenses": [],
        "analysisId": analysis_id,
    }
    results = []
    print_map = {}

    def paginate(page=1):
        params["page"] = page
        result = client.execute(query, variable_values=params)
        packages = result.get("packages", {})
        package_edges = packages.get("edges", [])
        total_count = packages.get("totalCount", 0)

        for e in package_edges:
            n = e.get("node", {})
            vulnerabilities = n.get("vulnerabilities", {})
            vulnerabilities_edges = vulnerabilities.get("edges", [])
            vulnerabilities_formatted = []
            for v in vulnerabilities_edges:
                vulnerability_node = v.get("node", {})
                cve_id = vulnerability_node.get("originalId", "")
                fixed_by = vulnerability_node.get("fixedBy", []) or []
                fixed_versions = ", ".join(fixed_by)
                severity = vulnerability_node.get("severity", "Unknown")

                if len(fixed_by) == 0:
                    fixed_versions = "No Fixable Versions"

                output = f"{cve_id} {severity} ({fixed_versions})"
                vulnerabilities_formatted.append(output)

            vulnerabilities = "\n\n".join(vulnerabilities_formatted)

            all_licenses = n.get("licenses", [])
            all_licenses_formatted = []
            for l in all_licenses:
                license = l.get("expression", "")
                all_licenses_formatted.append(license)
            licenses = ", ".join(all_licenses_formatted)

            p = {
                "package_name": n.get("name", ""),
                "license": licenses,
                "ecosystem": n.get("ecosystem", ""),
                "version": n.get("version", ""),
                "critical": n.get("vulnerabilityCount", {}).get("critical", 0),
                "high": n.get("vulnerabilityCount", {}).get("high", 0),
                "medium": n.get("vulnerabilityCount", {}).get("medium", 0),
                "low": n.get("vulnerabilityCount", {}).get("low", 0),
                "info": n.get("vulnerabilityCount", {}).get("info", 0),
                "none": n.get("vulnerabilityCount", {}).get("none", 0),
                "unknown": n.get("vulnerabilityCount", {}).get("unknown", 0),
            }
            row = [
                p["package_name"],
                p["version"],
                p["license"],
                p["ecosystem"],
                p["critical"],
                p["high"],
                p["medium"],
                p["low"],
                p["info"],
                p["none"],
                p["unknown"],
                vulnerabilities,
            ]
            results.append(row)
            print_percentage(len(results), total_count, print_map)

        if result["packages"]["pageInfo"]["hasNextPage"]:

            page = page + 1
            return paginate(page)

    paginate(1)
    return results


def get_available_resources():
    resources_file_path = "./available_resources.json"
    available_resources = {}
    if not os.path.exists(resources_file_path):
        raise FileNotFoundError(
            "Error: ./available_resources.json not found. Please run '$ python get_resources.py' first."
        )

    with open(resources_file_path, "r") as file:
        available_resources = json.load(file)

    return available_resources


def get_extraction_targets(available_resources, selected_resource_map):
    extraction_targets = []
    for organization in available_resources:
        for resource in available_resources[organization]:
            project_name = resource.get("projectName")
            complete_name = f"{organization}-{project_name}"
            if complete_name in selected_resource_map:
                extraction_item = {
                    "name": complete_name,
                    "analysis_id": resource.get("analysisId"),
                }
                extraction_targets.append(extraction_item)

    if len(extraction_targets) == 0:
        raise ValueError(
            "No analysis ids found.. please modify the selected_resources variable to include resources that exist in ./available_resources.json in main.py"
        )

    return extraction_targets


def get_selected_resource_map(selected_resources):
    selected_resource_map = {}
    for resource in selected_resources:
        organization = resource.get("organization")
        project_name = resource.get("project")
        complete_name = f"{organization}-{project_name}"
        selected_resource_map[complete_name] = resource
    return selected_resource_map


def print_percentage(current, total, print_map):
    percentage = round((current / total) * 100)
    if percentage == 0:
        return
    divisible_by_10 = percentage % 10 == 0

    if divisible_by_10:
        if print_map.get(percentage) is None:
            print(f"{percentage}% loaded...")
            print_map[percentage] = True
