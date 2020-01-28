control 'V-62259' do
  title "mgmt-users.properties file permissions must be set to allow access to
authorized users only."
  desc  "The mgmt-users.properties file contains the password hashes of all
users who are in a management role and must be protected.  Application servers
have the ability to specify that the hosted applications utilize shared
libraries. The application server must have a capability to divide roles based
upon duties wherein one project user (such as a developer) cannot modify the
shared library code of another project user. The application server must also
be able to specify that non-privileged users cannot modify any shared library
code at all."
  impact 0.5
  tag "gtitle": 'SRG-APP-000133-AS-000092'
  tag "gid": 'V-62259'
  tag "rid": 'SV-76749r1_rule'
  tag "stig_id": 'JBOS-AS-000210'
  tag "cci": ['CCI-001499']
  tag "documentable": false
  tag "nist": ['CM-5 (6)', 'Rev_4']
  tag "check": "The mgmt-users.properties files are located in the standalone
or domain configuration folder.

The $JBOSS_HOME default is /opt/bin/widfly

$JBOSS_HOME;/domain/configuration/mgmt-users.properties.
$JBOSS_HOME;/standalone/configuration/mgmt-users.properties.

Identify users who have access to the files using relevant OS commands.

Obtain documentation from system admin identifying authorized users.

Owner can be full access.
Group can be full access.
All others must have execute permissions only.

If the file permissions are not configured so as to restrict access to only
authorized users, or if documentation that identifies authorized users is
missing, this is a finding."
  tag "fix": "Configure the file permissions to allow access to authorized
users only.
Owner can be full access.
Group can be full access.
All others must have execute permissions only."
  tag "fix_id": 'F-68179r1_fix'
  describe file("#{ input('jboss_home') }/standalone/configuration/mgmt-users.properties") do
    it { should_not be_readable.by('others') }
  end
  describe file("#{ input('jboss_home') }/standalone/configuration/mgmt-users.properties") do
    it { should_not be_writable.by('others') }
  end
end
