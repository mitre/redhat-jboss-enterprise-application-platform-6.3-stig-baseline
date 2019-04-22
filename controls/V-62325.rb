control "V-62325" do
  title "Production Wildfly servers must be supported by the vendor."
  desc  "The Wildfly product is available as Open Source; however, the Red Hat
  vendor provides updates, patches and support for the JBoss product.  It is
  imperative that patches and updates be applied to Wildfly in a timely manner as
  many attacks against Wildfly focus on unpatched systems.  It is critical that
  support be obtained and made available."
  impact 0.7
  tag "gtitle": "SRG-APP-000456-AS-000266"
  tag "gid": "V-62325"
  tag "rid": "SV-76815r1_rule"
  tag "stig_id": "JBOS-AS-000680"
  tag "cci": ["CCI-002605"]
  tag "documentable": false
  tag "nist": ["SI-2 c", "Rev_4"]
  tag "check": "Interview the system admin and have them either show documented
  proof of current support, or have them demonstrate their ability to access the
  Red Hat Enterprise Support portal.

  Verify Red Hat  support includes coverage for the Wildfly product.

  If there is no current and active support from the vendor, this is a finding."
  tag "fix": "Obtain vendor support from Red Hat."
  tag "fix_id": "F-68245r1_fix"
  impact 0.0
  describe "Wildfly is the open-source, community version of JBoss and does not include RedHat support, therefore this control is not applicable" do
    skip "Wildfly is the open-source, community version of JBoss and does not include RedHat support, therefore this control is not applicable"
  end
end

