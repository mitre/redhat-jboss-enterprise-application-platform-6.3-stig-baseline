CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)

control "V-62335" do
  title "Wildfly must be configured to generate log records for privileged
  activities."
  desc  "
    Without generating log records that are specific to the security and
  mission needs of the organization, it would be difficult to establish,
  correlate, and investigate the events relating to an incident or identify those
  responsible for one.

      Privileged activities would occur through the management interface.  This
  interface can be web-based or can be command line utilities.  Whichever method
  is utilized by the application server, these activities must be logged.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000504-AS-000229"
  tag "gid": "V-62335"
  tag "rid": "SV-76825r1_rule"
  tag "stig_id": "JBOS-AS-000705"
  tag "cci": ["CCI-000172"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly
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
  tag "fix_id": "F-68255r1_fix"
  describe 'The wildfly server setting: generate log records for privileged activities' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end  
end