control "V-62313" do
  title "Production Wildfly servers must log when failed application deployments
  occur."
  desc  "
  Without logging the enforcement of access restrictions against changes to
  the application server configuration, it will be difficult to identify
  attempted attacks, and a log trail will not be available for forensic
  investigation for after-the-fact actions.  Configuration changes may occur to
  any of the modules within the application server through the management
  interface, but logging of actions to the configuration of a module outside the
  application server is not logged.

      Enforcement actions are the methods or mechanisms used to prevent
  unauthorized changes to configuration settings. Enforcement action methods may
  be as simple as denying access to a file based on the application of file
  permissions (access restriction). Log items may consist of lists of actions
  blocked by access restrictions or changes identified after the fact.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000381-AS-000089"
  tag "gid": "V-62313"
  tag "rid": "SV-76803r1_rule"
  tag "stig_id": "JBOS-AS-000550"
  tag "cci": ["CCI-001814"]
  tag "documentable": false
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  ls /core-service=management/access=audit/logger=audit-log

  If \"enabled\" = false, this is a finding."
  tag "fix": "Launch the jboss-cli management interface substituting standalone
  or domain for <CONFIG> based upon the server installation.

  $JBOSS_HOME;/<CONFIG>/bin/jboss-cli

  connect to the server and run the following command:

  /core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"
  tag "fix_id": "F-68233r1_fix"

  connect = attribute('connection')

  describe 'The Wildfly server setting: log when failed application deployments occur' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
