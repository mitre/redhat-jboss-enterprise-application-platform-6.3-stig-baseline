control 'V-62311' do
  title "Production Wildfly servers must not allow automatic application
  deployment."
  desc  "
    When dealing with access restrictions pertaining to change control, it
  should be noted that any changes to the software and/or application server
  configuration can potentially have significant effects on the overall security
  of the system.

      Access restrictions for changes also include application software libraries.

      If the application server provides automatic code deployment capability,
  (where updates to applications hosted on the application server are
  automatically performed, usually by the developers' IDE tool), it must also
  provide a capability to restrict the use of automatic application deployment.
  Automatic code deployments are allowable in a development environment, but not
  in production.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000380-AS-000088'
  tag "gid": 'V-62311'
  tag "rid": 'SV-76801r1_rule'
  tag "stig_id": 'JBOS-AS-000545'
  tag "cci": ['CCI-001813']
  tag "documentable": false
  tag "nist": ['CM-5 (1)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  ls /subsystem=deployment-scanner/scanner=default

  If \"scan-enabled\"=true, this is a finding."
  tag "fix": "Determine the JBoss server configuration as being either
  standalone or domain.

  Launch the relevant jboss-cli management interface substituting standalone or
  domain for <CONFIG>

  $JBOSS_HOME;/<CONFIG>/bin/jboss-cli

  connect to the server and run the command:

  /subsystem=deployment-scanner/scanner=default:write-attribute(name=scan-enabled,value=false)"
  tag "fix_id": 'F-68231r1_fix'

  connect = input('connection')

  describe 'The wildfly application deployment scanner' do
  subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /subsystem=deployment-scanner/scanner=default").stdout }
    it { should_not match(%r{scan-enabled=true}) }
  end
end
