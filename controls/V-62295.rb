control 'V-62295' do
  title "The Wildfly server must be configured to restrict access to the web
  servers private key to authenticated system administrators."
  desc  "
    The cornerstone of the PKI is the private key used to encrypt or digitally
  sign information.

      If the private key is stolen, this will lead to the compromise of the
  authentication and non-repudiation gained through PKI because the attacker can
  use the private key to digitally sign documents and can pretend to be the
  authorized user.

      Both the holders of a digital certificate and the issuing authority must
  protect the computers, storage devices, or whatever they use to keep the
  private keys. Java-based application servers utilize the Java keystore, which
  provides storage for cryptographic keys and certificates. The keystore is
  usually maintained in a file stored on the file system.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000176-AS-000125'
  tag "gid": 'V-62295'
  tag "rid": 'SV-76785r1_rule'
  tag "stig_id": 'JBOS-AS-000320'
  tag "cci": ['CCI-000186']
  tag "documentable": false
  tag "nist": ['IA-5 (2) (b)', 'Rev_4']
  tag "check": "The default location for the keystore used by the Wildfly vault
  is the $JBOSS_HOME;/vault/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  If a vault keystore has been created, by default it will be in the file:
  $JBOSS_HOME;/vault/vault.keystore.  The file stores a single key, with the
  default alias vault, which will be used to store encrypted strings, such as
  passwords, for Wildfly EAP.

  Browse to the Wildfly vault folder using the relevant OS commands.
  Review the file permissions and ensure only system administrators and Wildfly
  users are allowed access.

  Owner can be full access
  Group can be full access
  All others must be restricted to execute access or no permission.

  If non-system administrators are allowed to access the $JBOSS_HOME;/vault/
  folder, this is a finding."
  tag "fix": "Configure the application server OS file permissions on the
  corresponding private key to restrict access to authorized accounts or roles."
  tag "fix_id": 'F-68215r1_fix'
  describe directory("#{ attribute('jboss_home') }/vault") do
    it { should_not be_readable.by('others') }
  end
  describe directory("#{ attribute('jboss_home') }/vault") do
    it { should_not be_writable.by('others') }
  end
end
