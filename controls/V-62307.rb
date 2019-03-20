CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)

control "V-62307" do
  title "The Wildfly server must be configured to log all admin activity."
  desc  "
    In order to be able to provide a forensic history of activity, the
application server must ensure users who are granted a privileged role or those
who utilize a separate distinct account when accessing privileged functions or
data have their actions logged.

    If privileged activity is not logged, no forensic logs can be used to
establish accountability for privileged actions that occur on the system.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000343-AS-000030"
  tag "gid": "V-62307"
  tag "rid": "SV-76797r1_rule"
  tag "stig_id": "JBOS-AS-000480"
  tag "cci": ["CCI-002234"]
  tag "documentable": false
  tag "nist": ["AC-6 (9)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly.

The $JBOSS_HOME default is /opt/bin/widfly

Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.
Run the command:

/core-service=management/access=audit:read-resource(recursive=true)

Under the \"logger\" => {audit-log} section of the returned response:
If \"enabled\" => false, this is a finding"
  tag "fix": "Launch the jboss-cli management interface substituting standalone
or domain for <CONFIG> based upon the server installation.

$JBOSS_HOME;/<CONFIG>/bin/jboss-cli

connect to the server and run the following command:

/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"
  tag "fix_id": "F-68227r1_fix"
  describe 'The wildfly server setting to log all admin activity' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end