import helpers
import os
import csv

# EDIT THIS
selected_resources = [
    {"organization": "thefrenchbear", "project": "zzz"},
    {"organization": "thefrenchbear", "project": "winnipeg"},
]
# END EDIT

if len(selected_resources) == 0:
    raise ValueError(
        "No resources selected.. please modify the selected_resources variable in main.py"
    )


def main():
    boost_client = helpers.get_client()
    helpers.create_artifacts_folder()
    helpers.create_timestamp_folder()
    available_resources = helpers.get_available_resources()
    selected_resource_map = helpers.get_selected_resource_map(selected_resources)
    extraction_targets = helpers.get_extraction_targets(
        available_resources, selected_resource_map
    )

    for extraction_target in extraction_targets:
        analysis_id = extraction_target.get("analysis_id")
        name = extraction_target.get("name")

        print(f"Extracting SBOM for {name}...")

        sbom_options = {
            "analysis_id": analysis_id,
            "client": boost_client,
        }
        sbom_results = helpers.get_sbom(sbom_options)
        sbom_results.sort(key=lambda x: x[0].lower())

        headers = [
            "Library Name",
            "Version",
            "License",
            "Ecosystem",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
            "None",
            "Unknown",
            "Vulnerabilities",
        ]

        sbom_results.insert(0, headers)

        filename = f"{name}-sbom-{helpers.timestamp}.csv"
        full_path = os.path.join(helpers.timestamp_folder, filename)

        with open(full_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerows(sbom_results)


if __name__ == "__main__":
    main()
