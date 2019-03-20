control "V-62297" do
  title "The Wildfly server must separate hosted application functionality from
  application server management functionality."
  desc  "
      The application server consists of the management interface and hosted
  applications.  By separating the management interface from hosted applications,
  the user must authenticate as a privileged user to the management interface
  before being presented with management functionality.  This prevents
  non-privileged users from having visibility to functions not available to the
  user.  By limiting visibility, a compromised non-privileged account does not
  offer information to the attacker or functionality and information needed to
  further the attack on the application server.

      Wildfly is designed to operate with separate application and management
  interfaces.
      The Wildfly server is started via a script.  To start the JBoss server in
  domain mode, the admin will execute the $JBOSS_HOME;/bin/domain.sh or
  domain.bat script.

  The $JBOSS_HOME default is /opt/bin/widfly

      To start the Wildfly server in standalone mode, the admin will execute
  $JBOSS_HOME;/bin/standalone.bat or standalone.sh.

      Command line flags are used to specify which network address is used for
  management and which address is used for public/application access.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000211-AS-000146"
  tag "gid": "V-62297"
  tag "rid": "SV-76787r1_rule"
  tag "stig_id": "JBOS-AS-000355"
  tag "cci": ["CCI-001082"]
  tag "documentable": false
  tag "nist": ["SC-2", "Rev_4"]
  tag "check": "If Wildfly is not started with separate management and public
  interfaces, this is a finding.

  Review the network design documents to identify the IP address space for the
  management network.

  Use relevant OS commands and administrative techniques to determine how the
  system administrator starts the JBoss server.  This includes interviewing the
  system admin, using the \"ps -ef|grep\" command for UNIX like systems or
  checking command line flags and properties on batch scripts for Windows
  systems.



  The \"-b\" flag specifies the public address space.
  The \"-bmanagement\" flag specifies the management address space.

  Example:
  $JBOSS_HOME;/bin/standalone.sh -bmanagement 10.10.10.35 -b 192.168.10.25

  If Wildfly is not started with separate management and public interfaces, this is
  a finding."
  tag "fix": "Start the application server with a -bmanagement and a -b flag so
  that admin management functionality and hosted applications are separated.

  Refer to section 4.9 in the Wildfly Installation Guide for specific
  instructions on how to start the Wildfly server as a service."
  tag "fix_id": "F-68217r1_fix"
  bind_mgmt_address = command("grep jboss.bind.address.management /opt/wildfly/standalone/configuration/service.properties | awk -F'=' '{print $2}' ").stdout
  public_bind_address = command("grep jboss.bind.address /opt/wildfly/standalone/configuration/service.properties | grep -v management | awk -F'=' '{print $2}' ").stdout
  describe 'The wildfly bind management address' do
    subject { bind_mgmt_address }
    it { should_not eq public_bind_address }
  end
end