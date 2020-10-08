control 'V-62323' do
  title "Wildfly must be configured to use an approved cryptographic algorithm in
  conjunction with TLS."
  desc  "
    Preventing the disclosure or modification of transmitted information
  requires that application servers take measures to employ approved cryptography
  in order to protect the information during transmission over the network. This
  is usually achieved through the use of Transport Layer Security (TLS), SSL VPN,
  or IPSec tunnel.

    If data in transit is unencrypted, it is vulnerable to disclosure and
  modification. If approved cryptographic algorithms are not used, encryption
  strength cannot be assured.

    FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

    TLS must be enabled, and non-FIPS-approved SSL versions must be disabled.
  NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000440-AS-000167'
  tag "gid": 'V-62323'
  tag "rid": 'SV-76813r2_rule'
  tag "stig_id": 'JBOS-AS-000655'
  tag "cci": ['CCI-002421']
  tag "documentable": false
  tag "nist": ['SC-8 (1)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.

  Validate that the TLS protocol is used for HTTPS connections.
  Run the command:

  \"ls /subsystem=web/connector=https/ssl=configuration\"

  Review the cipher suites.  The following suites are acceptable as per NIST
  800-52r1 section 3.3.1 - Cipher Suites.  Refer to the NIST document for a
  complete list of acceptable cipher suites.  The source NIST document and
  approved encryption algorithms/cipher suites are subject to change and should
  be referenced.

  AES_128_CBC
  AES_256_CBC
  AES_128_GCM
  AES_128_CCM
  AES_256_CCM

  If the cipher suites utilized by the TLS server are not approved by NIST as per
  800-52r1, this is a finding."
  tag "fix": "Reference section 4.6 of the Wildfly Security Guide located
  on the Red Hat vendor's website for step-by-step instructions on establishing
  SSL encryption on Wildfly.

  The overall steps include:

  1. Add an HTTPS connector.
  2. Configure the SSL encryption certificate and keys.
  3. Set the Cipher to an approved algorithm."
  tag "fix_id": 'F-68243r1_fix'

  connect = input('connection')

  cipher_suites = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /subsystem=undertow/server=default-server/https-listener=https/").stdout
  describe.one do
    describe 'The wildfly cryptographic algorithm used for TLS' do
      subject { cipher_suites }
      it { should match(%r{enabled-cipher-suites=(AES_((128)|(256))_CBC)|(AES_((128)|(256))_GCM)|(AES_((128)|(256))_CCM)|(AES_((128)|(256))_CCM)}) }
    end
    describe 'The wildfly cryptographic algorithm used for TLS' do
      subject { cipher_suites }
      it { should match(%r{enabled-cipher-suites=AES_((128)|(256))_CBC}) }
    end
    describe 'The wildfly cryptographic algorithm used for TLS' do
      subject { cipher_suites }
      it { should match(%r{enabled-cipher-suites=CBC:AES_128_GCM}) }
    end
    describe 'The wildfly cryptographic algorithm used for TLS' do
      subject { cipher_suites }
      it { should match(%r{enabled-cipher-suites=AES_((128)|(256))_CCM}) }
    end
  end
end
