CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)

control "V-62333" do
  title "Wildfly must be configured to generate log records when
  successful/unsuccessful logon attempts occur."
  desc  "
    Logging the access to the application server allows the system
  administrators to monitor user accounts.  By logging successful/unsuccessful
  logons, the system administrator can determine if an account is compromised
  (e.g., frequent logons) or is in the process of being compromised (e.g.,
  frequent failed logons) and can take actions to thwart the attack.

      Logging successful logons can also be used to determine accounts that are
  no longer in use.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000503-AS-000228"
  tag "gid": "V-62333"
  tag "rid": "SV-76823r1_rule"
  tag "stig_id": "JBOS-AS-000700"
  tag "cci": ["CCI-000172"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Log on to the OS of the JBoss server with OS permissions that
  allow access to JBoss.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.
  Run the command:

  For a Managed Domain configuration:
  \"ls
  host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  For a Standalone configuration:
  \"ls
  /core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  If \"enabled\" = false, this is a finding."
  tag "fix": "Launch the jboss-cli management interface.
  Connect to the server by typing \"connect\", authenticate as a user in the
  Superuser role, and run the following command:

  For a Managed Domain configuration:
  \"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  For a Standalone configuration:
  \"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\""
  tag "fix_id": "F-68253r1_fix"
  describe 'The wildfly setting: generate log records when successful/unsuccessful logon attempts occur' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end  
end