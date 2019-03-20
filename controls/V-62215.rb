CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)

control "V-62215" do
  title "HTTPS must be enabled for Wildfly web interfaces."
  desc  "
    Encryption is critical for protection of remote access sessions. If
encryption is not being used for integrity, malicious users may gain the
ability to modify the application server configuration. The use of cryptography
for ensuring integrity of remote access sessions mitigates that risk.

    Application servers utilize a web management interface and scripted
commands when allowing remote access. Web access requires the use of TLS, and
scripted access requires using ssh or some other form of approved cryptography.
Application servers must have a capability to enable a secure remote admin
capability.

    FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

    FIPS 140-2 approved TLS versions must be enabled, and non-FIPS-approved SSL
versions must be disabled.

    NIST SP 800-52 specifies the preferred configurations for government
systems.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000015-AS-000010"
  tag "gid": "V-62215"
  tag "rid": "SV-76705r1_rule"
  tag "stig_id": "JBOS-AS-000015"
  tag "cci": ["CCI-001453"]
  tag "documentable": false
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly.

Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

The $JBOSS_HOME default is /opt/bin/widfly

Run the jboss-cli script.
Connect to the server and authenticate.

Review the web subsystem and ensure that HTTPS is enabled.
Run the command:

For a managed domain:
\"ls /profile=<PROFILE_NAME>/subsystem=web/connector=\"

For a standalone system:
\"ls /subsystem=web/connector=\"

If \"https\" is not returned, this is a finding."
  tag "fix": "Follow procedure \"4.4.  Configure the Wildfly Web Server to use
HTTPS.\"  The detailed procedure is found in the Wildfly Security Guide
available at the vendor's site, RedHat.com.  An overview of steps is provided
here.

1. Obtain or generate DoD-approved SSL certificates.
2. Configure the SSL certificate using your certificate values.
3. Set the SSL protocol to TLS V1.1 or V1.2."
  tag "fix_id": "F-68135r1_fix"
  describe 'HTTPS for Wildfly web interfaces' do
  subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /subsystem=undertow/server=default-server/https-listener=https").stdout }
    it { should match(%r{enabled=true}) }
  end
end

