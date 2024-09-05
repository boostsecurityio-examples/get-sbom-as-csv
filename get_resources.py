import json
import os
import csv
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport

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
# Select your transport with a defined url endpoint
transport = AIOHTTPTransport(
    url="https://api.boostsecurity.io/sbom-inventory/graphql", headers=headers
)


sbom_client = Client(transport=transport, fetch_schema_from_transport=True)


def get_list_repos():
    query = gql(
        """
query getListRepos($first: Int, $after: String, $last: Int, $before: String, $page: Int, $search: String, $orgName: String, $projectName: String, $packageIds: [String!], $withVulnerabilities: Boolean, $orderBy: [AnalysesOrder!], $locateAnalysisId: String) {
  analyses(
    first: $first
    after: $after
    last: $last
    before: $before
    page: $page
    filters: {search: $search, asset: {organizationName: $orgName, projectName: $projectName}, packageIds: $packageIds, withVulnerabilities: $withVulnerabilities}
    locateAnalysisId: $locateAnalysisId
    orderBy: $orderBy
  ) {
    totalCount
    edges {
      node {
        accountId
        analysisId
        assetLabel
        timestamp
        scmProvider
        organizationName
        projectName
        branchName
        commitId
        packageCount
        vulnerabilityCount {
          critical
          high
          medium
          low
          info
          none
          unknown
          __typename
        }
        __typename
      }
      cursor
      __typename
    }
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
      __typename
    }
    __typename
  }
}
    """
    )
    params = {
        "first": 100,
        "search": "",
        "withVulnerabilities": False,
    }
    results = {}

    def paginate(page=1):
        params["page"] = page
        result = sbom_client.execute(query, variable_values=params)
        r = result.get("analyses", {}).get("edges", [])

        for e in r:
            n = e.get("node", {})

            organization_nmae = n.get("organizationName", "")
            if results.get(organization_nmae) is None:
                results[organization_nmae] = []

            entry_item = {
                "projectName": n.get("projectName", ""),
                "analysisId": n.get("analysisId", ""),
            }

            results[organization_nmae].append(entry_item)

        if result["analyses"]["pageInfo"]["hasNextPage"]:

            page = page + 1
            return paginate(page)

    paginate(1)
    return results


resources = get_list_repos()
with open(f"./available_resources.json", "w") as file:
    json.dump(resources, file, indent=4)
