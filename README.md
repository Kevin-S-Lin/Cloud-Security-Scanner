# Main Page
Several Folders
- Local Baseline Scans is being run on a laptop in a local environment and is meant to a baseline monothlithic cronbased architecture.
- AWS is meant to hold scripts to utilize Infrastructure as Code to deploy an image vulnerability scanning service.

## To-Do List
- [ ] Objective 1
- [ ] Objective 2
- [ ] Objective 3

``` bash
aws ecr get-login-password --region us-east-1 \
| docker login \
    --username AWS \
    --password-stdin 322615215464.dkr.ecr.us-east-1.amazonaws.com
```