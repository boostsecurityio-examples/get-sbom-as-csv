# SBOM as CSV

Export an SBOM from a BoostSecurityio project as a CSV file.

1.  [Acquire a Boost API Token](https://app.boostsecurity.io/settings?tab=Application+Keys) and assign it to the following environment variable: `BOOST_API_TOKEN`

    Example: `$ export BOOST_API_TOKEN={your_api_token}`

2.  Install dependencies with pip

    Example: `$ pip install -r requirements.txt`

3.  Run `get_resources.py` in order to view the available resources that you can acquire an SBOM for.

    Example: `$ python get_resources.py`

    The execution of this script will create a file titled 'available_resources.json' that will allow you to see the available organizations and associated projects that you can use in the `main.py` file to acquire an SBOM for.

4.  Adjust `selected_resources` in `main.py` (as of writing, this is line 6) to specify which projects you would like to get SBOMs for.

    Example:

        selected_resources = [
            {"organization": "thefrenchbear", "project": "winnipeg"},
            {"organization": "your_organization", "project": "your_project"}
        ]

5.  Run `main.py` to generate SBOMs

    Example: `$ python main.py`

6.  Review the generated SBOMs in the artifacts directory.
