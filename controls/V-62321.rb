CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)

control "V-62321" do
  title "Wildfly must be configured to use an approved TLS version."
  desc  "
      Preventing the disclosure of transmitted information requires that the
  application server take measures to employ some form of cryptographic mechanism
  in order to protect the information during transmission.  This is usually
  achieved through the use of Transport Layer Security (TLS).

      Wildlfy relies on the underlying SSL implementation running on the OS.  This
  can be either Java based or OpenSSL.  The SSL protocol setting determines which
  SSL protocol is used.  SSL has known security vulnerabilities, so TLS should be
  used instead.

      If data is transmitted unencrypted, the data then becomes vulnerable to
  disclosure.  The disclosure may reveal user identifier/password combinations,
  website code revealing business logic, or other user personal information.

      FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

      TLS must be enabled, and non-FIPS-approved SSL versions must be disabled.
  NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000439-AS-000155"
  tag "gid": "V-62321"
  tag "rid": "SV-76811r2_rule"
  tag "stig_id": "JBOS-AS-000650"
  tag "cci": ["CCI-002418"]
  tag "documentable": false
  tag "nist": ["SC-8", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.

  Validate that the TLS protocol is used for HTTPS connections.
  Run the command:

  \"ls /subsystem=web/connector=https/ssl=configuration\"

  If a TLS V1.1 or V1.2 protocol is not returned, this is a finding."
  tag "fix": "Reference section 4.6 of the Wildfly Security Guide located
  on the Red Hat vendor's web site for step-by-step instructions on establishing
  SSL encryption on Wildfly.

  The overall steps include:

  1. Add an HTTPS connector.
  2. Configure the SSL encryption certificate and keys.
  3. Set the protocol to TLS V1.1 or V1.2."
  tag "fix_id": "F-68241r1_fix"
  describe 'The wildfly enabled TLS versions' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /subsystem=undertow/server=default-server/https-listener=https/").stdout }
    it { should match(%r{enabled-protocols=TLSv1.[12]:TLSv1.[12]}) }
  end
end