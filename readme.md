CloudGPT
==================

## AWS vulnerability scanner ##
Scan customer managed AWS policies for vulnerabilities using ChatGPT.

Follow me on Twitter ([Mike Felch - @ustayready](https://twitter.com/ustayready)) 

## Basic Usage ##
### Requires OpenAI API key
```
usage: scan.py [-h] --key KEY [--profile PROFILE] [--redact]

Retrieve all customer managed policies and check the default policy version for vulnerabilities

optional arguments:
  -h, --help         show this help message and exit
  --key KEY          OpenAI API key
  --profile PROFILE  AWS profile name to use (default: default)
  --redact           Redact sensitive information in the policy document (default: True)
  
CloudGPT the AWS vulnerability scanner
```
*python scan.py --key ABC --profile AWSPROFILE*
         
## Installation ##
You can install and run with the following command:

```bash
$ git clone https://github.com/ustayready/cloudgpt
$ cd cloudgpt
~/cloudgpt $ virtualenv -p python3 .
~/cloudgpt $ source bin/activate
(cloudgpt) ~/cloudgpt $ python scan.py
```




