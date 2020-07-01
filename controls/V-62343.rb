control 'V-62343' do
  title "The Wildlfy server must be configured to use DoD- or CNSS-approved PKI
  Class 3 or Class 4 certificates."
  desc  "Class 3 PKI certificates are used for servers and software signing
  rather than for identifying individuals. Class 4 certificates are used for
  business-to-business transactions. Utilizing unapproved certificates not issued
  or approved by DoD or CNS creates an integrity risk. The application server
  must utilize approved DoD or CNS Class 3 or Class 4 certificates for software
  signing and business-to-business transactions."
  impact 0.5
  tag "gtitle": 'SRG-APP-000514-AS-000137'
  tag "gid": 'V-62343'
  tag "rid": 'SV-76833r1_rule'
  tag "stig_id": 'JBOS-AS-000730'
  tag "cci": ['CCI-002450']
  tag "documentable": false
  tag "nist": ['SC-13', 'Rev_4']
  tag "check": "Interview the administrator to determine if Wildlfy is using
  certificates for PKI.  If Wildlfy is not performing any PKI functions, this
  finding is NA.

  The CA certs are usually stored in a file called cacerts located in the
  directory $JAVA_HOME/lib/security.  If the file is not in this location, use a
  search command to locate the file, or ask the administrator where the
  certificate store is located.

  Open a dos shell or terminal window and change to the location of the
  certificate store.  To view the certificates within the certificate store, run
  the command (in this example, the keystore file is cacerts.): keytool -list -v
  -keystore ./cacerts

  Locate the \"OU\" field for each certificate within the keystore.  The field
  should contain either \"DoD\" or \"CNSS\" as the Organizational Unit (OU).

  If the OU does not show that the certificates are DoD or CNSS supplied, this is
  a finding."
  tag "fix": "Configure the application server to use DoD- or CNSS-approved
  Class 3 or Class 4 PKI certificates."
  tag "fix_id": 'F-68263r1_fix'

  java_cert = input('java_cert')

  certs = command("keytool -list -v -keystore #{java_cert}").stdout
  describe.one do
    describe 'The wildfly server PKI certificate' do
      subject { certs }
      it { should match(%r{OU=DoD}) }
    end
    describe 'The wildfly server PKI certificate' do
      subject { certs }
      it { should match(%r{OU=CNSS}) }
    end
  end
end
