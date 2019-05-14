control 'V-62263' do
  title "Google Analytics must be disabled in EAP Console."
  desc  "
    The Google Analytics feature aims to help Red Hat EAP team understand how
  customers are using the console and which parts of the console matter the most
  to the customers. This information will, in turn, help the team to adapt the
  console design, features, and content to the immediate needs of the customers.

    Sending analytical data to the vendor introduces risk of unauthorized data
  exfiltration.  This capability must be disabled.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-AS-000095'
  tag "gid": 'V-62263'
  tag "rid": 'SV-76753r1_rule'
  tag "stig_id": 'JBOS-AS-000225'
  tag "cci": ['CCI-000381']
  tag "documentable": false
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "check": "Open the EAP web console by pointing a web browser to
  HTTPS://<SERVERNAME>:9443 or HTTP://<SERVERNAME>:9990

  Log on to the admin console using admin credentials.
  On the bottom right-hand side of the screen, select \"Settings\".

  If the \"Enable Data Usage Collection\" box is checked, this is a finding."
  tag "fix": "Using the EAP web console, log on using admin credentials.
  On the bottom right-hand side of the screen, select \"Settings\",
  uncheck the \"Enable Data Usage Collection\" box, and save the configuration."
  tag "fix_id": 'F-68183r1_fix'
  describe 'A manual review is required to ensure Google Analytics is disable in the EAP console' do
    skip 'A manual review is required to ensure Google Analytics is disable in the EAP console'
  end
end
