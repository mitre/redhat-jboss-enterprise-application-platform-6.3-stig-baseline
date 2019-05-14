control "V-62303" do
  title "Network access to HTTP management must be disabled on domain-enabled
  application servers not designated as the domain controller."
  desc  "
    When configuring Wildfly application servers into a domain configuration,
  HTTP management capabilities are not required on domain member servers as
  management is done via the server that has been designated as the domain
  controller.

      Leaving HTTP management capabilities enabled on domain member servers
  increases the attack surfaces; therefore, management services on domain member
  servers must be disabled and management services performed via the domain
  controller.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000316-AS-000199"
  tag "gid": "V-62303"
  tag "rid": "SV-76793r1_rule"
  tag "stig_id": "JBOS-AS-000470"
  tag "cci": ["CCI-002322"]
  tag "documentable": false
  tag "nist": ["AC-17 (9)", "Rev_4"]
  tag "check": "Log on to each of the Wildfly domain member servers.

  Note: Sites that manage systems using the Wildfly Operations Network client
  require HTTP interface access.  It is acceptable that the management console
  alone be disabled rather than disabling the entire interface itself.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the $JBOSS_HOME;/bin/jboss-cli command line interface utility and connect
  to the Wildfly server.
  Run the following command:
  ls /core-service=management/management-interface=httpinterface/

  If \"console-enabled=true\", this is a finding."
  tag "fix": "Run the $JBOSS_HOME;/bin/jboss-cli command line interface
  utility.
  Connect to the Wildfly server and run the following command.
  /core-service=management/management-interface=httpinterface/:write-attribute(name=console-enabled,value=false)

  Successful command execution returns
  {\"outcome\" => \"success\"}, and future attempts to access the management
  console via web browser at <SERVERNAME>:9990 will result in no access to the
  admin console."
  tag "fix_id": "F-68223r1_fix"

  connect = attribute('connection')

  describe 'The wildfly HTTP management interface' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/management-interface=http-interface").stdout }
    it { should_not match(%r{console-enabled=true}) }
  end
end
