CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)


control "V-62287" do
  title "The Wildfly Password Vault must be used for storing passwords or other
  sensitive configuration information."
  desc  "Wildfly has a Password Vault to encrypt sensitive strings, store
  them in an encrypted keystore, and decrypt them for applications and
  verification systems. Plain-text configuration files, such as XML deployment
  descriptors, need to specify passwords and other sensitive information. Use the
  Wildfly EAP Password Vault to securely store sensitive strings in plain-text
  files."
  impact 0.5
  tag "gtitle": "SRG-APP-000171-AS-000119"
  tag "gid": "V-62287"
  tag "rid": "SV-76777r1_rule"
  tag "stig_id": "JBOS-AS-000295"
  tag "cci": ["CCI-000196"]
  tag "documentable": false
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  \"ls /core-service=vault\"

  If \"code=undefined\" and \"module=undefined\",
  this is a finding."
  tag "fix": "Configure the application server to use the java keystore and
  Wildfly vault as per section 11.13.1 -Password Vault System in the
  Wildfly-Administration_and_Configuration_Guide-en-US
  document.

  1. Create a java keystore.
  2. Mask the keystore password and initialize the password vault.
  3. Configure JBoss to use the password vault."
  tag "fix_id": "F-68207r1_fix"

  code = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=vault").stdout
  vault_module = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=vault").stdout
  vault_options = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=vault").stdout

  describe 'The wildfly password vault code' do
    subject { code }
    it { should_not match(%r{code=undefined}) }
  end
  describe 'The wildfly password vault module' do
    subject { vault_module }
    it { should_not match(%r{module=undefined}) }
  end
  describe 'The wildfly password vault options' do
    subject { vault_options }
    it { should match(%r{vault-options={"KEYSTORE_URL" => "[a-zA-Zа-яА-Я0-9_!\/.]*","KEYSTORE_PASSWORD" => "MASK-[\w.]*","KEYSTORE_ALIAS" => "\w*","SALT" => "[\w\d]*","ITERATION_COUNT" => "\d*","ENC_FILE_DIR" => "[a-zA-Zа-яА-Я0-9_!\/.]*"}}) }
  end
end