control 'V-62235' do
  title "Wildfly must be configured to initiate session logging upon startup."
  desc  "Session logging activities are developed, integrated, and used in
consultation with legal counsel in accordance with applicable federal laws,
Executive Orders, directives, policies, or regulations."
  impact 0.5
  tag "gtitle": 'SRG-APP-000092-AS-000053'
  tag "gid": 'V-62235'
  tag "rid": 'SV-76725r1_rule'
  tag "stig_id": 'JBOS-AS-000095'
  tag "cci": ['CCI-001464']
  tag "documentable": false
  tag "nist": ['AU-14 (1)', 'Rev_4']
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
Superuser role and run the following command:

For a Managed Domain configuration:
\"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

For a Standalone configuration:
\"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\""
  tag "fix_id": 'F-68155r1_fix'

  connect = attribute('connection')

  describe 'Wildfly initiate session logging upon startup' do
    subject { command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
