control "V-62317" do
  title "Wildfly must be configured to use DoD PKI-established certificate
  authorities for verification of the establishment of protected sessions."
  desc  "
    Untrusted Certificate Authorities (CA) can issue certificates, but they may
  be issued by organizations or individuals that seek to compromise DoD systems
  or by organizations with insufficient security controls. If the CA used for
  verifying the certificate is not a DoD-approved CA, trust of this CA has not
  been established.

      The DoD will only accept PKI certificates obtained from a DoD-approved
  internal or external certificate authority. Reliance on CAs for the
  establishment of secure sessions includes, for example, the use of SSL/TLS
  certificates.  The application server must only allow the use of DoD
  PKI-established certificate authorities for verification.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000427-AS-000264"
  tag "gid": "V-62317"
  tag "rid": "SV-76807r1_rule"
  tag "stig_id": "JBOS-AS-000625"
  tag "cci": ["CCI-002470"]
  tag "documentable": false
  tag "nist": ["SC-23 (5)", "Rev_4"]
  tag "check": "Locate the cacerts file for the JVM.  This can be done using
  the appropriate find command for the OS and change to the directory where the
  cacerts file is located.

  To view the certificates stored within this file, execute the java command
  \"keytool -list -v -keystore ./cacerts\".
  Verify that the Certificate Authority (CA) for each certificate is DoD-approved.

  If any certificates have a CA that are not DoD-approved, this is a finding."
  tag "fix": "Locate the cacerts file for the JVM.  This can be done using the
  appropriate find command for the OS and change to the directory where the
  cacerts file is located.

  Remove the certificates that have a CA that is non-DoD approved, and import DoD
  CA-approved certificates."
  tag "fix_id": "F-68237r1_fix"
  dod_cn = command("keytool -list -v -keystore /usr/lib/jvm/java-1.8.0/jre/lib/security/cacerts").stdout
  eca_cn = command("keytool -list -v -keystore /usr/lib/jvm/java-1.8.0/jre/lib/security/cacerts").stdout

  describe.one do
    describe 'The Wildfly DoD PKI-established certificate' do
      subject { dod_cn }
      it { should match(%r{CN=DoD}) }
    end
    describe 'The Wildfly DoD PKI-established certificate' do
      subject { eca_cn }
      it { should match(%r{CN=ECA}) }
    end
  end
end