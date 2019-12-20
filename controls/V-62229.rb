control 'V-62229' do
  title "Wildfly management interfaces must be secured."
  desc  "Wildfly utilizes the concept of security realms to secure the management
interfaces used for Wildfly server administration.  If the security realm
attribute is omitted or removed from the management interface definition,
access to that interface is no longer secure.  The Wildfly management interfaces
must be secured."
  impact 0.7
  tag "gtitle": 'SRG-APP-000033-AS-000024'
  tag "gid": 'V-62229'
  tag "rid": 'SV-76719r1_rule'
  tag "stig_id": 'JBOS-AS-000075'
  tag "cci": ['CCI-000213']
  tag "documentable": false
  tag "nist": ['AC-3', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly.
Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

The $JBOSS_HOME default is /opt/bin/widfly
Run the jboss-cli script.
Connect to the server and authenticate.

Identify the management interfaces.  To identity the management interfaces, run
the following command:

For standalone servers:
\"ls /core-service=management/management-interface=\"

For managed domain installations:
\"ls /host=HOST_NAME/core-service=management/management-interface=\"

By default, Wildfly provides two management interfaces; they are named
\"NATIVE-INTERFACE\" and \"HTTP-INTERFACE\".  The system may or may not have
both interfaces enabled.  For each management interface listed as a result of
the previous command, append the name of the management interface to the end of
the following command.

For a standalone system:

\"ls /core-service=management/management-interface=<MANAGEMENT INTERFACE NAME>\"

For a managed domain:

\"ls /host=HOST_NAME/core-service=management/management-interface=<MANAGEMENT
INTERFACE NAME>\"

If the \"security-realm=\" attribute is not associated with a management realm,
this is a finding."
  tag "fix": "Identify the security realm used for management of the system.
By default, this is called \"Management Realm\".

If a management security realm is not already available, reference the Wildfly
system administration guide for instructions on how to create a
security realm for management purposes.  Create the management realm, and
assign authentication and authorization access restrictions to the management
realm.

Assign the management interfaces to the management realm."
  tag "fix_id": 'F-68149r1_fix'

  connect = attribute('connection')

  mgmt_interfaces = command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\ /core-service=management/management-interface=").stdout.split("\n")

  mgmt_interfaces.each do |interface|
    describe "Wildfly management interface: #{interface}" do
      subject { command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/management-interface=#{interface}").stdout }
      it { should match(%r{security-realm=ManagementRealm}) }
    end
  end
  if mgmt_interfaces.empty?
    impact 0.0
    describe 'There are no wildfly management interfaces, therefore this control is Not Applicable' do
      skip 'There are no wildfly management interfaces, therefore this control is Not Applicable'
    end
  end
end
