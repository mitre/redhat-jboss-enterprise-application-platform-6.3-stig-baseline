# red-hat-jboss-eap-6.3-stig-baseline

InSpec profile to validate the secure configuration of JBOSS Wildfly EAP server, against [DISA](https://iase.disa.mil/stigs/)'s JBOSS Security Technical Implementation Guide (STIG).

## Container-Ready: Profile updated to adapt checks when the running against a containerized instance of MongoDB, based on reference container: (docker pull registry1.dso.mil/ironbank/opensource/jboss/wildfly:latest)

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __SSH__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs file for the profile to run correctly. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

``` yaml
# For an out of the box installation of JBOSS: 
connection: '--connect'

# If targeting a remote JBOSS instance: 
connection: '--connect --controller=<IP_OF_REMOTE_JBOSS_HOST>:9990'

# If for example the JBOSS instance has been hardened with the wildfly-hardening cookbook (https://github.com/mitre/chef-red-hat-jboss-eap-6.3-stig-baseline) set the connection to the following:
connection: '-Djavax.net.ssl.trustStore=/opt/wildfly/standalone/configuration/a.jks --connect -u=test1 -p=test'

# Disables long running controls
disable_slow_controls: false

# The process name for jboss
jboss_process_name: ''

# the path for $JBOSS_HOME
jboss_home: ''

# List of authorized users with the auditor role.
auditor_role_users: []

# List of authorized users with the administrator role.
administrator_role_users: []

# List of authorized users with the SuperUser role.
superuser_role_users: []

# group owner of files/directories
wildfly_group: ''

# user owner of files/directories
wildly_owner: ''

# List of  authorized applications.
approved_applications: []

# List of  authorized nginx modules.
wildfly_ports: []

# List of authorized users with the deployer role.
deployer_role_users: []

# List of authorized users with the maintainer role.
maintainer_role_users: []

# List of authorized users with the monitor role.
monitor_role_users: []

# List of authorized users with the operator role.
operator_role_users: []

# Set to true if ldap is being used
ldap: false

# Set to true if widlfy is being used as a high-availability cluster
high_availability: false

# location on hard disk of the java cacert file
java_cert: ''
```

### For further examples of how to utilize the JBOSS CLI 
[JBOSS CLI Docs](https://docs.jboss.org/author/display/WFLY/Command+Line+Interface)

# Running This Baseline Directly from Github

If this is a fresh JBOSS installation, run the following command from the command line of the system hosting the JBOSS instance:

``` bash
# Need to run the command 
$ /bin/sh /opt/wildfly/bin/jboss-cli.sh --connect 
# Enter P to permanetely accept the certificate
```

On the runner

Against a _**locally-hosted**_ instance (i.e., InSpec installed on the target)
```
inspec exec https://github.com/mitre/redhat-jboss-enterprise-application-platform-6.3-stig-baseline/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>
```
Against a _**docker-containerized**_ instance (i.e., InSpec installed on the node hosting the container):
```bash
inspec exec https://github.com/mitre/redhat-jboss-enterprise-application-platform-6.3-stig-baseline/archive/master.tar.gz -t docker://instance_id --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/redhat-jboss-enterprise-application-platform-6.3-stig-baseline
inspec archive redhat-jboss-enterprise-application-platform-6.3-stig-baseline
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd redhat-jboss-enterprise-application-platform-6.3-stig-baseline
git pull
cd ..
inspec archive redhat-jboss-enterprise-application-platform-6.3-stig-baseline --overwrite
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/redhat-jboss-enterprise-application-platform-6.3-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
