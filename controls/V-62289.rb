CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)

control "V-62289" do
  title "Wildfly KeyStore and Truststore passwords must not be stored in clear
  text."
  desc  "
    Access to the Wildfly Password Vault must be secured, and the password used
  to access must be encrypted.  There is a specific process used to generate the
  encrypted password hash.  This process must be followed in order to store the
  password in an encrypted format.

      The admin must utilize this process in order to ensure the Keystore
  password is encrypted.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000171-AS-000119"
  tag "gid": "V-62289"
  tag "rid": "SV-76779r1_rule"
  tag "stig_id": "JBOS-AS-000300"
  tag "cci": ["CCI-000196"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "The default location for the keystore used by the Wildfly vault
  is the $JBOSS_HOME;/vault/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  If a vault keystore has been created, by default it will be in the file:
  $JBOSS_HOME;/vault/vault.keystore.  The file stores a single key, with the
  default alias vault, which will be used to store encrypted strings, such as
  passwords, for JBoss EAP.

  Have the system admin provide the procedure used to encrypt the keystore
  password that unlocks the keystore.

  If the system administrator is unable to demonstrate or provide written process
  documentation on how to encrypt the keystore password, this is a finding."
  tag "fix": "Configure the application server to mask the java keystore
  password as per the procedure described in section 11.13.3 -Password Vault
  System in the
  Wildfly-Administration_and_Configuration_Guide-en-US
  document."
  tag "fix_id": "F-68209r1_fix"
  describe 'The wildfly keystore and trustore vault options' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=vault").stdout }
    it { should match(%r{vault-options={"KEYSTORE_URL" => "[a-zA-Zа-яА-Я0-9_!\/.]*","KEYSTORE_PASSWORD" => "MASK-[\w.]*","KEYSTORE_ALIAS" => "\w*","SALT" => "[\w\d]*","ITERATION_COUNT" => "\d*","ENC_FILE_DIR" => "[a-zA-Zа-яА-Я0-9_!\/.]*"}}) }
  end
end