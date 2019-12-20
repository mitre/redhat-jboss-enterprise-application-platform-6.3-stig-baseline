control 'V-62275' do
  title "Wildfly application and management ports must be approved by the PPSM
CAL."
  desc  "
    Some networking protocols may not meet organizational security requirements
to protect data and components.

    Application servers natively host a number of various features, such as
management interfaces, httpd servers and message queues. These features all run
on TCPIP ports. This creates the potential that the vendor may choose to
utilize port numbers or network services that have been deemed unusable by the
organization. The application server must have the capability to both
reconfigure and disable the assigned ports without adversely impacting
application server operation capabilities. For a list of approved ports and
protocols, reference the DoD ports and protocols website at
https://powhatan.iiie.disa.mil/ports/cal.html.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000142-AS-000014'
  tag "gid": 'V-62275'
  tag "rid": 'SV-76765r1_rule'
  tag "stig_id": 'JBOS-AS-000255'
  tag "cci": ['CCI-000382']
  tag "documentable": false
  tag "nist": ['CM-7 b', 'Rev_4']
  tag "check": "Open the EAP web console by pointing a web browser to
HTTPS://<Servername>:9443 or HTTP://<Servername>:9990

Log on to the admin console using admin credentials
Select the \"Configuration\" tab
Expand the \"General Configuration\" sub system by clicking on the +
Select \"Socket Binding\"
Select the \"View\" option next to \"standard-sockets\"
Select \"Inbound\"

Review the configured ports and determine if they are all approved by the PPSM
CAL.

If all the ports are not approved by the PPSM CAL, this is a finding."
  tag "fix": "Open the EAP web console by pointing a web browser to
HTTPS://<Servername>:9990

Log on to the admin console using admin credentials
Select the \"Configuration\" tab
Expand the \"General Configuration\" sub system by clicking on the +
Select \"Socket Binding\"
Select the \"View\" option next to \"standard-sockets\"
Select \"Inbound\"

Select the port that needs to be reconfigured and select \"Edit\"."
  tag "fix_id": 'F-68195r1_fix'

  wildfly_ports = input('wildfly_ports')

  wildfly_ports.each do |port|
    describe file("#{ input('jboss_home') }/standalone/configuration/service.properties") do
      its('content') { should include port }
    end
    describe file("#{ input('jboss_home') }/standalone/configuration/service.properties") do
      it { should exist}
    end
  end
end
