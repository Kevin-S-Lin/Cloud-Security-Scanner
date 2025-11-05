# Local Baseline Scans
This is mainly to test the logic and runtime running scans in a monolithic time-based structure as opposed to the event driven elastic environment of the cloud.

Listed in a text file is the current specs of the machine running the tests locally. (It is an old laptop, but it still should exceed the specs of the free tier options in AWS)

Currently:
- Takes a list of images in images.txt (Currently arbitrary, but later this list should be generated autonomously)
- Runs a Trivy Scan 3 times just to get baseline scanning times
- Logs the summary of the results into a CSV file
- Stores the raw reports in JSON into a folder

Future:
- Add cronbased checks for changes to images.txt so there is no need to pull and scan all the images again
- Add integrations to the CI/CD pipeline
- Add system monitoring to the old laptop

**Important to compare the cost of the machine (CAPEX) to the cost of AWS cloud services (OPEX)**