HIGH_AVAILABILITY= attribute(
  'high_availability',
  description: 'Set to true if widlfy is being used as a high-availability cluster',
  default: 'false'
)

control "V-62319" do
  title "The Wildfly server, when hosting mission critical applications, must be
  in a high-availability (HA) cluster."
  desc  "A MAC I system is a system that handles data vital to the
  organization's operational readiness or effectiveness of deployed or
  contingency forces.  A MAC I system must maintain the highest level of
  integrity and availability.  By HA clustering the application server, the
  hosted application and data are given a platform that is load-balanced and
  provides high availability."
  impact 0.5
  tag "gtitle": "SRG-APP-000435-AS-000069"
  tag "gid": "V-62319"
  tag "rid": "SV-76809r1_rule"
  tag "stig_id": "JBOS-AS-000640"
  tag "cci": ["CCI-002385"]
  tag "documentable": false
  tag "nist": ["SC-5", "Rev_4"]
  tag "check": "Interview the system admin and determine if the applications
  hosted on the application server are mission critical and require load
  balancing (LB) or high availability (HA).

  If the applications do not require LB or HA, this requirement is NA.

  If the documentation shows the LB or HA services are being provided by another
  system other than the application server, this requirement is NA.

  If applications require LB or HA, request documentation from the system admin
  that identifies what type of LB or HA configuration has been implemented on the
  application server.

  Ask the system admin to identify the components that require protection.  Some
  options are included here as an example.  Bear in mind the examples provided
  are not complete and absolute and are only provided as examples.  The
  components being made redundant or HA by the application server will vary based
  upon application availability requirements.

  Examples are:
  Instances of the Application Server
  Web Applications
  Stateful, stateless and entity Enterprise Java Beans (EJBs)
  Single Sign On (SSO) mechanisms
  Distributed Cache
  HTTP sessions
  JMS and Message Services.

  If the hosted application requirements specify LB or HA and the Wildfly server
  has not been configured to offer HA or LB, this is a finding."
  tag "fix": "Configure the application server to provide LB or HA services for
  the hosted application."
  tag "fix_id": "F-68239r1_fix"
  describe 'The wildfly configuration file used' do
      subject { command ('ps -ef | grep wildfly | grep -v grep | grep -v chef').stdout }
      it {should match /[\w\b\D\d\W]* -c=standalone-full.ha.xml [\w\b\D\d\W]*/}

      before do
      skip if HIGH_AVAILABILITY == 'false'
  end

    end 
end
