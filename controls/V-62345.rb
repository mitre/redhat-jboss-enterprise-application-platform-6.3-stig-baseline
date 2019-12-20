control 'V-62345' do
  title "Wildfly servers must be configured to roll over and transfer logs on a
  minimum weekly basis."
  desc  "
    Information stored in one location is vulnerable to accidental or
  incidental deletion or alteration.  Protecting log data is important during a
  forensic investigation to ensure investigators can track and understand what
  may have occurred.  Off-loading should be set up as a scheduled task but can be
  configured to be run manually, if other processes during the off-loading are
  manual.

      Off-loading is a common process in information systems with limited log
  storage capacity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000515-AS-000203'
  tag "gid": 'V-62345'
  tag "rid": 'SV-76835r1_rule'
  tag "stig_id": 'JBOS-AS-000735'
  tag "cci": ['CCI-001851']
  tag "documentable": false
  tag "nist": ['AU-4 (1)', 'Rev_4']
  tag "check": "If the Wildfly server is configured to use a Syslog Handler, this
  is not a finding.

  Log on to the OS of the Wildfly server with OS permissions that allow access to
  Wildfly.

  The $JBOSS_HOME default is /opt/bin/widfly

  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script.
  Connect to the server and authenticate.

  Determine if there is a periodic rotating file handler.

  For a domain configuration run the following command; where <SERVERNAME> is a
  variable for all of the servers in the domain.  Usually \"server-one\",
  \"server-two\", etc.:

  \"ls
  /host=master/server=<SERVERNAME>/subsystem=logging/periodic-rotating-file-handler=\"

  For a standalone configuration run the command:
  \"ls /subsystem=logging/periodic-rotating-file-handler=\"

  If the command does not return \"FILE\", this is a finding.

  Review the $JBOSS_HOME;/standalone/log folder for the existence of rotated
  logs, and ask the admin to demonstrate how rotated logs are packaged and
  transferred to another system on at least a weekly basis."
  tag "fix": "Open the web-based management interface by opening a browser and
  pointing it to HTTPS://<EAP_SERVER>:9990/

  Authenticate as a user with Admin rights.
  Navigate to the \"Configuration\" tab.
  Expand + Subsystems.
  Expand + Core.
  Select \"Logging\".
  Select the \"Handler\" tab.
  Select  \"Periodic\".

  If a periodic file handler does not exist, reference Wildfly admin guide for
  instructions on how to create a file handler that will rotate logs on a daily
  basis.
  Create scripts that package and off-load log data at least weekly."
  tag "fix_id": 'F-68265r1_fix'

  connect = input('connection')

  describe 'The wildfly periodic roating file handler setting' do
    subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ subsystem=logging/periodic-rotating-file-handler=").stdout }
    it { should match(%r{FILE}) }
  end
end
