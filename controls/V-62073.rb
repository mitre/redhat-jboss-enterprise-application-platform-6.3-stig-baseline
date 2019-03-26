CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)

control "V-62073" do
  title "HTTP management session traffic must be encrypted."
  desc  "
    Types of management interfaces utilized by the Wildfly EAP application server
include web-based HTTP interfaces as well as command line-based management
interfaces.  In the event remote HTTP management is required, the access must
be via HTTPS.

    This requirement is in conjunction with the requirement to isolate all
management access to a restricted network.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000014-AS-000009"
  tag "gid": "V-62073"
  tag "rid": "SV-76563r1_rule"
  tag "stig_id": "JBOS-AS-000010"
  tag "cci": ["CCI-000068"]
  tag "documentable": false
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly. Using the relevant OS commands and syntax, cd to the
$JBOSS_HOME;/bin/ folder.

The $JBOSS_HOME default is /opt/bin/widfly

Run the jboss-cli script. Connect to the server and authenticate.

For a standalone configuration run the following command:
\"ls /core-service=management/management-interface=http-interface\"

If \"secure-socket-binding\"=undefined, this is a finding.

For a domain configuration run the following command:
\"ls /host=master/core-service=management/management-interface=http-interface\"

If \"secure-port\" is undefined, this is a finding."
  tag "fix": "Follow the specific instructions in the Red Hat Security Guide
for EAP version 6.3 to configure the management console for HTTPS.

This involves the following steps.
1. Create a keystore in JKS format.
2. Ensure the management console binds to HTTPS.
3. Create a new Security Realm.
4. Configure Management Interface to use new security realm.
5. Configure the management console to use the keystore.
6. Restart the EAP server."
  tag "fix_id": "F-67993r1_fix"
  describe 'The wildfly HTTP management session traffic configuration' do
  subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/management-interface=http-interface").stdout }
    it { should_not match /secure-socket-binding=undefined/ }
  end 
end

