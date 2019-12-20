# red-hat-jboss-eap-6.3-stig-baseline

InSpec profile to validate the secure configuration of JBOSS Wildfly EAP server, against [DISA](https://iase.disa.mil/stigs/)'s **JBOSS Security Technical Implementation Guide (STIG)**.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.


### Run with remote profile:
You may choose to run the profile via a remote url, this has the advantage of always being up to date.
The disadvantage is you may wish to modify controls, which is only possible when downloaded.
Also, the remote profile is unintuitive for passing in attributes, which modify the default values of the profile.
``` bash
inspec exec https://github.com/mitre/red-hat-jboss-eap-6.3-stig-baseline
```

Another option is to download the profile then run it, this allows you to edit specific instructions and view the profile code.

#### Run these commands on the Target / JBOSS
``` bash
# Need to run the command 
$ /bin/sh /opt/wildfly/bin/jboss-cli.sh --connect 
# Enter P to permanetely accept the certificate

```

#### Run the following commands on the runner with InSpec

##### Download the repo and configure
``` bash
# Clone Inspec Profile
$ git clone https://github.com/mitre/red-hat-jboss-eap-6.3-stig-baseline

#If running the profile before running the wildfly-hardening cookbook set the following in red-hat-jboss-eap-6.3-stig-baseline/attributes.yml:
connection: '--connect'

# If running the profile after running the wildfy-hardening cookbook set the following in red-hat-jboss-eap-6.3-stig-baseline/attributes.yml:
connection: '-Djavax.net.ssl.trustStore=/opt/wildfly/standalone/configuration/a.jks --connect -u=test1 -p=test'

```

##### Running the Profile
To run it locally
```bash
# How to run 
$ inspec exec red-hat-jboss-eap-6.3-stig-baseline --attrs red-hat-jboss-eap-6.3-stig-baseline/attributes.yml
```

How to run on a remote target
```bash
# How to run 
$ inspec exec red-hat-jboss-eap-6.3-stig-baseline -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --attrs red-hat-jboss-eap-6.3-stig-baseline/attributes.yml
```

How to run on a remote target using pem key
```bash
# How to run 
$ inspec exec red-hat-jboss-eap-6.3-stig-baseline -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT -i PEM_KEY --attrs red-hat-jboss-eap-6.3-stig-baseline/attributes.yml
```

How to run on docker container
```bash
Inspec exec red-hat-jboss-eap-6.3-stig-baseline -t docker://DOCKER_CONTAINER_ID --attrs red-hat-jboss-eap-6.3-stig-baseline/
```


## Attributes (Configuration)
You may alter the default settings of the profile by creating/modifying a yaml 
encoded 'attributes' file. The following yaml code details the currently 
supported attributes, and can also be viewed as the attributes.yml file in this 
repository.

``` yaml
#command to use when the wildfly cli is configured with a password
#-u=<username to login in a>
#-p=<password>

#If running the profile before running the wildfly-hardening cookbook set the following in red-hat-jboss-eap-6.3-stig-baseline/attributes.yml:
connection: '--connect'

#If running the profile after running the wildfy-hardening cookbook set this in red-hat-jboss-eap-6.3-stig-baseline/attributes.yml:
connection: '-Djavax.net.ssl.trustStore=/opt/wildfly/standalone/configuration/a.jks --connect -u=test1 -p=test'
high_availability: 'false'
ldap: 'false'



#node.default['wildfly-hardening']['c'] = '--connect'

```

## Authors
- Alicia Sturtevant

## Special Thanks

- The MITRE InSpec Team

## License 

This project is licensed under the terms of the [Apache 2.0 license](https://github.com/mitre/wildfly-stig-baseline/blob/master/LICENSE.md).

### NOTICE

© 2019 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
