# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#

import re


threat_regex = re.compile("'(?P<detection_identity_name>.*?)'.+'(?P<filePath>.*?)'")

# What to do with the different types of event. None indicates drop the event, otherwise a regex extracts the
# various fields and inserts them into the event dictionary.
TYPE_HANDLERS = {
    "Event::Endpoint::Threat::Detected": threat_regex,
    "Event::Endpoint::Threat::CleanedUp": threat_regex,
    "Event::Endpoint::Threat::HIPSDismissed": threat_regex,
    "Event::Endpoint::Threat::HIPSDetected": threat_regex,
    "Event::Endpoint::Threat::PuaDetected": threat_regex,
    "Event::Endpoint::Threat::PuaCleanupFailed": threat_regex,
    "Event::Endpoint::Threat::CleanupFailed": threat_regex,
    "Event::Endpoint::Threat::CommandAndControlDismissed": threat_regex,
    "Event::Endpoint::Threat::HIPSCleanupFailed": threat_regex,
    "Event::Endpoint::DataLossPreventionUserAllowed":
        re.compile(u"An \u2033(?P<name>.+)\u2033.+ Username: (?P<user>.+?) {2}"
                   u"Rule names: \u2032(?P<rule>.+?)\u2032 {2}"
                   "User action: (?P<user_action>.+?) {2}Application Name: (?P<app_name>.+?) {2}"
                   "Data Control action: (?P<action>.+?) {2}"
                   "File type: (?P<file_type>.+?) {2}File size: (?P<file_size>\\d+?) {2}"
                   "Source path: (?P<file_path>.+)$"),

    "Event::Endpoint::NonCompliant": threat_regex,    # None == ignore the event
    "Event::Endpoint::Compliant": threat_regex,
    "Event::Endpoint::Device::AlertedOnly": None,
    "Event::Endpoint::UpdateFailure": None,
    "Event::Endpoint::SavScanComplete": None,
    "Event::Endpoint::Application::Allowed": threat_regex,
    "Event::Endpoint::UpdateSuccess": None,
    "Event::Endpoint::WebControlViolation": threat_regex,
    "Event::Endpoint::WebFilteringBlocked": threat_regex,
    "Event::Endpoint::UpdateRebootRequired": None,
    "Event::Endpoint::Registered": threat_regex,
    "Event::Endpoint::UserAutoCreated": None,
    "Event::Firewall::LostConnectionToSophosCentral": None,
    "Event::ZTNA::ZTNAGatewayUnreachable": None,
    "Event::Wireless::WifixAccessPoint::Common": None,
    "Event::CSWITCH::CSwitchDisconnected": None,
}


def update_fields(log, data):
    """
        Split 'name' field into multiple fields based on regex and field names specified in TYPE_HANDLERS
        Original 'name' field is replaced with the detection_identity_name field, if returned by regex.
    """

    if u'description' in data.keys():
        data[u'name'] = data[u'description']

    if data[u'type'] in TYPE_HANDLERS:
        prog_regex = TYPE_HANDLERS[data[u'type']]
        if not prog_regex:
            return
        result = prog_regex.search(data[u'name'])
        if not result:
            log("Failed to split name field for event type %r" % data[u'type'])
            return

        # Make sure record has a name field corresponding to the first field (for the CEF format)
        gdict = result.groupdict()
        if "detection_identity_name" in gdict:
            data[u'name'] = gdict["detection_identity_name"]

        # Update the record with the split out parameters
        data.update(result.groupdict())

# List of Events from https://support.sophos.com/support/s/article/KB-000038309?language=en_US
# Event::ADSync::Success	Active Directory synchronization succeeded
# Event::ADSync::Warning	Active Directory synchronization warning
# Event::ADSync::Error	Active Directory synchronization error
# Event::ADSync::TooLargeError	ADSync did not complete, the data sent to Sophos Central exceeds the maximum, reducing the number of items selected for synchronization.
# Event::CWG::Reprotected	Web Gateway Device re-protected
# Event::CWG::Registered	New Web Gateway Device registered
# Event::EDR.DarkBytes::CaseCreated	MDR threat case created; "{1}" detected
# Event::Endpoint::CloneDetected	The device has been detected as a duplicate device. For more information, go to the article referenced in the event.
# Event::Endpoint::Compliant	Policy in compliance {1}
# Event::Endpoint::NonCompliant	Policy non-compliance {1}
# Event::Endpoint::UpdateSuccess	Update succeeded
# Event::Endpoint::UpdateRebootRequired	Reboot recommended after software update
# Event::Endpoint::UpdateRebootUrgentlyRequired	Reboot required after software update
# Event::Endpoint::VirtualisationCertificateRenewal	Reboot required after certificate renewal
# Event::Endpoint::UpdateFailure::UPDATED_SUCCESSFULLY	Updated successfully
# Event::Endpoint::UpdateFailure::INSTALL_FAILED	Failed to install {1}: {2}
# Event::Endpoint::UpdateFailure::INSTALL_CAUGHT_ERROR	Installation caught error {1}.
# Event::Endpoint::UpdateFailure::DOWNLOAD_FAILED	Download of {1} failed from server {2}.
# Event::Endpoint::UpdateFailure::UPDATE_CANCELLED	The update was cancelled by the user.
# Event::Endpoint::UpdateFailure::RESTART_NEEDED	A restart is needed for updates to take effect.
# Event::Endpoint::UpdateFailure::UPDATE_SOURCE_MISSING	Updating failed because no update source has been specified.
# Event::Endpoint::UpdateFailure::PACKAGE_SOURCE_MISSING	ERROR: Could not find a source for updated package {1}
# Event::Endpoint::UpdateFailure::CONNECTION_ERROR	There was a problem while establishing a connection to the server  {1}.
# Event::Endpoint::UpdateFailure::PACKAGES_SOURCE_MISSING	ERROR: Could not find a source for updated packages.
# Event::Endpoint::UpdateFailure::PRODUCT_MISSING	Updating failed because {1} is missing.
# Event::Endpoint::UpdateFailure::ERROR_UPDATING_SOPHOS	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_UPDATING_NOT_SOPHOS	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_COPYING_FILES	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_UPDATING	Failed to apply updates.
# Event::Endpoint::UpdateFailure::ERROR_CHECKING_SOPHOS	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_CHECKING_VIA_HTTP	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_CHECKING_VIA_LAN	Failed to download updates.
# Event::Endpoint::UpdateFailure::ERROR_MOUNTING	Failed to download updates.
# Event::Endpoint::UpdateFailure::UPDATING_CANCELLED	The update was cancelled by the user.
# Event::Endpoint::UpdateFailure::RESTARTING	A restart is needed for updates to take effect.
# Event::Endpoint::UpdateFailure::SOCKET_ERROR	Sophos AutoUpdate is not running.
# Event::Endpoint::UpdateFailure::UNKNOWN_ERROR	Update failed ({1})
# Event::Endpoint::Application::Blocked	Controlled application blocked: {1} ({2})
# Event::Endpoint::Application::Allowed	Controlled application allowed: {1} ({2})
# Event::Endpoint::Application::Detected	Controlled application detected: {1} ({2})
# Event::Endpoint::NotProtected	Failed to protect {1}: {2}
# Event::Endpoint::Protected	New {1} protected: {2}
# Event::Endpoint::OutOfDate	Endpoint is out of date {1}
# Event::Endpoint::Registered	New endoint registered {1} {2}
# Event::Endpoint::Reprotected	Endont re-protected: {1} {2}
# Event::Endpoint::SavDisabled	Real time protection disabled
# Event::Endpoint::SavEnabled	Real time protection re-enabled
# Event::Endpoint::SavError	Error reported: {1}
# Event::Endpoint::SavFastScanComplete	Scan ''{1}'' completed
# Event::Endpoint::SavScanComplete	Scan ''{1}'' completed
# Event.Endpoint::SavSmartScanAborted	Scan ''{1}'' aborted
# Event.Endpoint::SavSmartScanComplete	Scan ''{1}'' completed
# Event.Endpoint::SavSmartScanStarted	Scan ''{1}'' started
# Event::Endpoint::UserAutoCreated	New user added automatically: {1}
# Event::Endpoint::DownloadReputationAutoAuthorised	Low reputation download automatically trusted from {1}
# Event::Endpoint::DownloadReputationAutoBlocked	Low reputation download automatically deleted from {1}
# Event::Endpoint::DownloadReputationUserAuthorised	User trusted low reputation download from {1}
# Event::Endpoint::DownloadReputationUserBlocked	User deleted low reputation download from {1}
# Event::Endpoint::Deduplicated::COMPUTER	Device has been de-duplicated from: 
# Event::Endpoint::Deduplicated::SERVER	Device has been de-duplicated from: 
# Event::Endpoint::Deduplicated::SECURITY_VM	Device has been de-duplicated from: 
# Event::Endpoint::Isolation::Isolated::SELF	Computer auto isolated due to red health
# Event::Endpoint::Isolation::Isolated::ADMIN	Computer isolated by an administrator {1}
# Event::Endpoint::Isolation::Isolated::ADMIN_UNKNOWN	Computer has been isolated
# Event::Endpoint::Isolation::UnIsolated::SELF	Computer removed from auto isolation
# Event::Endpoint::Isolation::UnIsolated::ADMIN	Computer removed from isolation by an administrator {1}
# Event::Endpoint::Isolation::UnIsolated::ADMIN_UNKNOWN	Computer has been removed from isolation
# Event::Endpoint::WebFilteringBlocked	Access has been blocked to ''{1}'' as ''{2}'' has been found at this website.
# Event::Endpoint::WebControlViolation::BLOCKED	''{1}'' blocked due to {2} ''{3}''
# Event::Endpoint::WebControlViolation::WARNED	''{1}'' warned due to {2} ''{3}''
# Event::Endpoint::WebControlViolation::PROCEEDED	User bypassed {2} block to ''{1}''
# Event::Endpoint::WebControlViolation::UNKNOWN	''{1}'' unknown violation
# Event::Endpoint::WindowsFirewall::Blocked	Application {1} was blocked by an endpoint firewall.
# Event::Endpoint::AppChange::1	Application installation: No changes
# Event::Endpoint::AppChange::2	Uninstalled application(s): {1}
# Event::Endpoint::AppChange::3	 Installed application(s): {1}
# Event::Endpoint::AppChange::4	Application installation: new application(s): {1}, removed: {2}
# Event::Endpoint::WindowsFirewall::Blocked	Application {1} was blocked by an endpoint firewall
# Event::Endpoint::UnsupportedOperatingSystem	The computer is running an operating system and service pack combination which is no longer supported. Upgrade to continue receiving protection.
# Event::Endpoint::ServiceNotRunning	One or more Sophos services are missing or not running.
# Event::Endpoint::ServiceRestored	All Sophos services are running.
# Event::Task::RenewApnsCertificate::1	Your APNS certificate will expire in {1} day/s.
# Event::Task::RenewApnsCertificate::2	Your APNS certificate will expire in 1 day.
# Event::Task::RenewApnsCertificate::3	Your APNS certificate will expire in less than a day.
# Event::Task::RenewApiToken::1	Your API token {2} will expire in {1} day/s.
# Event::Task::RenewApiToken::2	Your API token {1} has expired.
# Event::Task::RenewLicense	{1} license has expired on {2,date}
# Event::Task::SupportPortalOpen	Remote assistance is enabled
# Event::Task::ProtectEndpoints	Protect your devices
# Event::Task::SecurityIssue	Security issue detected
# Event::Endpoint::Device::AlertedOnly	Peripheral allowed: {1}
# Event::Endpoint::Device::Blocked	Peripheral blocked: {1}
# Event::Endpoint::Device::ReadOnly	Peripheral restricted to read-only: {1}
# Event::Endpoint::HeartbeatMissing	Sophos Firewall {1} reported computer not sending heartbeat signals
# Event::Endpoint::HeartbeatRestored	Sophos Firewall {1} reported computer resumed sending heartbeat signals
# Event::Endpoint::Mobile::EasDataMissing	Please add the Exchange information.
# Event::Endpoint::Mobile::Added	New mobile device added {1}
# Event::Endpoint::Mobile::Enrolled	New mobile device enrolled {1}
# Event::Endpoint::Mobile::EnrolledNewApp	New {1} app enrolled for endpoint {2}
# Event::Endpoint::Mobile::NowNonCompliant	The mobile device is now non compliant
# Event::Endpoint::Mobile::NowNonCompliant::0	The mobile device is now non compliant. Reason: {1}
# Event::Endpoint::Mobile::NowNonCompliant::GENERAL_BLACKLISTED_APPS	The mobile device is now non compliant. Forbidden app {1} installed.
# Event::Endpoint::Mobile::NowNonCompliant::GENERAL_WHITELISTED_APPS	The mobile device is now non compliant. Forbidden app {1} installed.
# Event::Endpoint.Mobile::NowNonCompliant::GENERAL_MANDATORY_APPS	The mobile device is now non compliant. Mandatory app {1} not installed.
# Event::Endpoint::Mobile::NowNonCompliant::UNKNOWN	The mobile device is now non compliant. Reason: {1}
# Event::Endpoint::Mobile::UnenrolledByUser	User unenrolled {1} app
# Event::Endpoint::Mobile::NowCompliant	The mobile device is now compliant.
# Event::Endpoint::Mobile::Unenrolled	App {1} has been unenrolled.
# Event::Endpoint::Mobile::PlaceholderMissing	Please add the information for placeholder {1}
# Event::Endpoint::Threat::Dismissed	Malware locally cleared: {1}
# Event::Endpoint::Threat::CleanedUp	Malware cleaned up: {1}
# Event::Endpoint::Threat::CommandAndControlDetected::1	Malicious traffic detected: {1} (Technical Support reference: {2})
# Event::Endpoint::Threat::CommandAndControlDetected::2	Sophos Firewall detected malicious traffic: {1} (Technical Support reference: {2})
# Event::Endpoint::Threat::CommandAndControlDetected::3	Malicious traffic detected: {1} ({2}) at {3}. Parent process: {4}.
# Event::Endpoint::Threat::CommandAndControlDismissed	Malicious traffic detection locally cleared: {1}
# Event::Endpoint::Threat::IpsInboundDetection	Malicious inbound network traffic blocked from a remote computer at {1} (Technical Support reference: {2})
# Event::Endpoint::Threat::IpsInboundDetection::1	Malicious outbound network traffic blocked (Technical Support reference: {1})
# Event::Endpoint::Threat::IpsInboundDetection::2	Malicious outbound network traffic blocked from {1} (Technical Support reference: {2})
# Event::Endpoint::CoreIpsClean	Network Traffic Protection cleaned up a threat
# Event::Endpoint::CoreIpsCleanFailed	Network Traffic Protection could not clean up a threat
# Event::Endpoint::Threat::HIPSCleanedUp	Running malware cleaned up: {1}
# Event::Endpoint::Threat::HIPSDetected	Running malware detected: {1}
# Event::Endpoint::Threat::HIPSDismissed	Running malware locally cleared: {1}
# Event::Endpoint::Threat::Detected	Malware detected: {1}
# Event::Endpoint::Threat::PuaDismissed	PUA locally cleared: {1}
# Event::Endpoint::Threat::PuaCleanedUp	PUA cleaned up: {1}
# Event::Endpoint::Threat::PuaDetected	PUA detected: {1}
# Event::Endpoint::Threat::LowRepAppDetected	Low reputation app detected: {1}
# Event::Endpoint::Threat::LowRepAppCleanedUp	Low reputation app cleaned up: {1}
# Event::Endpoint::HomeCookiesDeleted	
# Cookies deleted {1}
# Event::Endpoint::HomeCookiesDetected	Cookies found {1}
# Event::Endpoint::HomePuaRemnantsDeleted	Remnants deleted of Potentially Unwanted App: {1}
# Event::Endpoint::HomePuaRemnantsDetected	Remnants found of Potentially Unwanted App: {1}
# Event::Endpoint::HomeThreatRemnantsDeleted	
# Threat remnants deleted {1}
# Event::Endpoint::HomeThreatRemnantsDetected	
# Threat remnants found {1}
# Event::Endpoint::HomeStartStarted	Scan started
# Event::Endpoint::HomeStartFinished	Scan completed
# Event::Endpoint::HomeStartCancelled	Scan cancelled
# Event::Endpoint::HomeEndpointUninstalled	
# Device uninstalled
# Event::Endpoint::HmpaApplicationHijacking	''{1}'' application hijacking prevented in {2}
# Event::Endpoint::HmpaBehaviourPrevented	''{1}'' malicious behavior prevented in {2}
# Event::Endpoint::HmpaCameraMic	{1} was {2} after using {3}
# Event::Endpoint::HmpaCookiesDeleted	{1} of {2} tracking cookies deleted
# Event::Endpoint::HmpaCookiesDetected	Scan detected {1} cookies
# Event::Endpoint::HmpaCredGuard	We prevented credential theft in {1}
# Event::Endpoint::HmpaCredGuardResolved	Credential theft attempt resolved
# Event::Endpoint::HmpaCryptoGuard	CryptoGuard detected ransomware in {1}
# Event::Endpoint::HmpaCryptoGuardResolved	CryptoGuard unblocked process {1}
# Event::Endpoint::HmpaCryptoGuardSMB	CryptoGuard detected a ransomware attack from {1}
# Event::Endpoint::HmpaCryptoGuardSMBOrigin	CryptoGuard detected a ransomware attack from this device against {1}
# Event::Endpoint::HmpaCryptoGuardSMBResolved	CryptoGuard unblocked access to network shares from {1}
# Event::Endpoint::HmpaExploitPrevented	''{1}'' exploit prevented in {2}
# Event::Endpoint::HmpaMalwareDetected	Detected malware: {1}
# Event::Endpoint::HmpaMalwareCleanup	Deleted malware: {1}
# Event::Endpoint::HmpaPrivGuard	We prevented a privilege escalation exploit in {1}
# Event::Endpoint::HmpaPrivGuardResolved	Privilege escalation exploit resolved
# Event::Endpoint::HmpaPuaDetected	Detected PUA: {1}
# Event::Endpoint::HmpaPuaCleanup	{1} has been cleaned up
# Event::Endpoint::HmpaSafeBrowsing	Safe Browsing detected browser {1} has been compromised
# Event::Endpoint::HmpaScanCompleted	Scan completed
# Event::Endpoint::HmpaScanReboot	Reboot required for complete cleanup
# Event::Endpoint::HmpaScanStarted	Scan started
# Event::Endpoint::HmpaScanClean	Computer is clean
# Event::Endpoint::HmpaThreat	Safe Browsing detected a threat
# Event::Endpoint::IntensiveScanStarted	Scan started
# Event::Endpoint::IntensiveScanPartComplete	Scan stage one complete. Beginning stage two.
# Event::Endpoint::CoreAmsiBlocked::1	AMSI Protection blocked a threat: {1} at {2}
# Event::Endpoint::CoreAmsiBlocked::2	AMSI Protection blocked a threat: {1} at an unknown location.
# Event.Endpoint.CoreAmsiClean	AMSI Protection cleaned up a threat.
# Event.Endpoint.CoreAmsiCleanFailed	AMSI Protection could not clean up a threat.
# Event::Endpoint::CoreDetection	Malware detected: ''{2}'' at ''{1}''
# Event::Endpoint::CoreRemoteDetection	Malware ''{2}'' detected in network location ''{1}'' requires attention
# Event::Endpoint::CorePuaDetection	PUA detected: ''{2}'' at ''{1}''
# Event::Endpoint::CorePuaRemoteDetection	PUA ''{2}'' detected in network location ''{1}'' requires attention
# Event::Endpoint::CoreClean	Malware cleaned up: ''{2}'' at ''{1}''
# Event::Endpoint::CoreCleanFailed	Manual malware cleanup required: ''{2}'' at ''{1}''
# Event::Endpoint::CoreGenerateForensicSnapshot::1	Created a forensic snapshot
# Event::Endpoint::CoreGenerateForensicSnapshot::2	Created a forensic snapshot
# Event::Endpoint::CoreGenerateForensicSnapshotFailed::1	Could not create a forensic snapshot
# Event::Endpoint::CoreGenerateForensicSnapshotFailed::2	Could not create a forensic snapshot
# Event::Endpoint::CoreHmpaClean	Malware cleaned up: ''{2}'' at ''{1}''
# Event::Endpoint::CoreHmpaCleanFailed	Manual malware cleanup required: ''{2}'' at ''{1}''
# Event::Endpoint::CoreHmpaCleanNothingFound	Nothing found to clean up: ''{2}'' at ''{1}''
# Event::Endpoint::CoreHmpaReboot	Reboot required for complete cleanup: ''{2}'' at ''{1}''
# Event::Endpoint::CoreCleanNothingFound	No items were cleaned.
# Event::Endpoint::CorePuaClean	PUA cleaned up: ''{2}'' at ''{1}''
# Event::Endpoint::CorePuaCleanFailed
#  	Manual PUA cleanup required: ''{2}'' at ''{1}''
# Event::Endpoint::CorePuaCleanNothingFound	No items were cleaned.
# Event::Endpoint::CoreBlocklistClean	Blocked item cleaned up: ''{1}''
# Event::Endpoint::CoreBlocklistCleanFailed	Manual blocked item cleanup required: ''{1}''
# Event::Endpoint::CoreSystemClean	System cleaned up
# Event::Endpoint::CoreSystemCleanFailed	System Clean failed
# Event::Endpoint::CoreRestore	Restored: ''{1}'' and associated items
# Event::Endpoint::CoreRestoreFailed	Restore failed: ''{1}'' and associated items
# Event::Endpoint::CorePuaRestore	Restored: ''{1}'' and associated items
# Event::Endpoint::CorePuaRestoreFailed	Restore failed: ''{1}'' and associated items
# Event::Endpoint::CoreReboot	Reboot required for complete cleanup: ''{2}'' at ''{1}''
# Event::Endpoint::CorePuaReboot	Reboot required for complete PUA cleanup: ''{2}'' at ''{1}''
# Event::Endpoint::CoreOutbreak	Outbreak detected
# Event::Endpoint::CoreDismissed	Malware marked as resolved
# Event::Endpoint::CoreOutbreakDismissed	Outbreak marked as resolved
# Event::Endpoint::CoreUploadForensicSnapshot	Uploaded a forensic snapshot
# Event::Endpoint::CoreUploadForensicSnapshotFailed.1	Could not upload a forensic snapshot
# Event::Endpoint::CoreUploadForensicSnapshotFailed.2	Could not upload a forensic snapshot
# Event::Firewall::FirewallAdvancedThreatProtection	An attempt to communicate with a botnet or command and control server has been detected.
# Event::Firewall::FirewallGatewayDown	Firewall Gateway Down {1}
# Event::Firewall::FirewallGatewayUp	Firewall Gateway Up {1}
# Event::Firewall::FirewallHAStateDegraded	One of the HA nodes is down or in a degraded state, and high availability is not degraded.
# Event::Firewall::FirewallHAStateRestored	Both HA nodes are now connected and at full health.
# Event::Firewall::FirewallHighCPUUsage	The firewall's CPU has been at or above {1}% usage for more than {2} minutes
# Event::Firewall::FirewallHighDiskUsage	The firewall's Disk usage has been at {1}% for more than {2} minutes
# Event::Firewall::FirewallHighMemoryUsage	The firewall's memory usage has been at {1}% for more than {2} minutes
# Event::Firewall::FirewallMaxCPUUsage	The firewall's CPU has been at or above {1}% usage for more than {2} minutes
# Event::Firewall::FirewallMissingHeartbeat	An endpoint that previously had a Security Heartbeat, is still communicating on the network, but the Security Heartbeat has been lost.
# Event::Firewall::FirewallREDTunnelUp	Firewall RED tunnel connection restored {1}
# Event::Firewall::FirewallREDTunnelDown	Firewall RED tunnel down {1}
# Event::Firewall::FirewallVPNTunnelUp	Firewall VPN tunnel connection restored {1}
# Event::Firewall::Reconnected	The firewall connection to Sophos Central has been restored
# Event::Firewall::LostConnectionToSophosCentral	Firewall has not checked in with Sophos Central for the past {1} minutes
# Event::Firewall::FirewallUnAuthorizedToSophosCentral	Central firewall reporting has been disabled for this device.
# Event::Firewall::ReportingLicenseHADisable	Sophos has separated HA pair device(s) from the same group and shared allocation between them.
# Event::Firewall::ReportingGracePeriodStart	Central firewall reporting license has been expired and the extension period started.
# Event::Firewall::RenewalWithLesserQuantity	We have reduced the Central Firewall Reporting licenses allocated for your device/s.
# Event::Firewall::ReportingGracePeriodExtension	Your Central Firewall Reporting license has expired and {1} days extension period is over
# Event::Firewall::ReportingGracePeriodExpired	Your Central Firewall Reporting license extension period of {1} days is over
# Event::Firewall.ReportingXgsLicenseExpired	Your Central Firewall Reporting XGS license has expired.
# Event.Firewall::ReportingXgsLicenseNotification	Firewall Reporting XGS Licence will expire in {0} days.
# Event::Other::FirewallSubscriptionExpiringSoon	Subscriptions {1} are set to expire within the next {2} days.
# Event::Other::FirewallSubscriptionAlmostExpired	Subscriptions (1) are set to expire within the next week.
# Event::Other::FirewallSubscriptionExpired	Subscriptions {1} have recently expired.
# Event::Other::ZeroTouchCancelled	A local administrator has signed in and aborted the zero-touch process on this firewall.
# Event::Other::RegisteredInCentral	A new firewall has been successfully registered to Sophos Central.
# Event::Other::ManagementApprovalExpired	A firewall was awaiting management approval for more than 30 days, and the wait time has been expired.
# Event::Other::ManagementDisabled	Firewall management has been disabled for this firewall.
# Event::Other::DeregisteredFromSophosCentral	This firewall has been de-registered from Sophos Central.
# Event::Other::WaitingForApproval	A firewall has turned on Sophos Central management or reporting and is awaiting approval to be managed.
# Event::Other::FirewallFirmwareUpdateInProgress	A firmware update has been started on this firewall.
# Event::Other::FirewallFirmwareUpdateSuccessfullyFinished	A firmware update has been completed successfully, and the firewall is now ready to resume normal operation.
# Event::Other::FirewallFirmwareUpdateFailed	 A firmware update has failed to install successfully on the firewall.
# Event::Iaas::Log::AWS_ACCOUNT_ADDED	AWS account added ({1})
# Event::Iaas::Log::AWS_ACCOUNT_DELETED	AWS account deleted ({1})
# Event::Iaas::Log.BUCKET_HEALTH_CHANGED	S3 storage health is {2} for ''{1}''
# Event::Iaas::IaasError::INVALID_ACCOUNT_CREDENTIALS	Invalid AWS credentials ({1})
# Event::Iaas::IaasError::ACCOUNT_LOCKED	AWS account locked ({1})
# Event::Iaas::IaasError::NOT_AUTHORIZED_API	AWS account not authorized ({1})
# Event::Iaas::IaasError::INCORRECT_PERMISSIONS	Incorrect AWS details or IAM permissions ({1})
# Event::Iaas::IaasError::DUPLICATED_ACCOUNT	Duplicated AWS account ({1})
# Event::Iaas::IaasError::ACCOUNT_ID_CHANGED	AWS account ID changed ({1})
# Event::Iaas::IaasError::TOO_MANY_PERMISSIONS	Too many AWS IAM permissions ({1})
# Event::Iaas::IaasError::UNAUTHORIZED	Incorrect AWS IAM permissions ({1})
# Event::Iaas::IaasError::DEFAULT	AWS connection error ({1})
# Event::Iaas::BucketError.BUCKET_HEALTH_CHANGED	S3 storage health is {2} for ''{1}''
# Event::IaasAzure::AzureLog::AZURE_DIRECTORY_ADDED	Azure Active Directory added
# Event::IaasAzure::AzureLog::AZURE_DIRECTORY_REMOVED	Azure Active Directory removed
# Event::IaasAzure::AzureLog::AZURE_DIRECTORY_MODIFIED	Azure Active Directory modified
# Event::IaasAzure::AzureError::INVALID_CREDENTIALS	Invalid Azure credentials
# Event::IaasAzure::AzureError::UNKNOWN_ERROR	Azure connection error
# Event::Mobile::ApnsCertificateExpired	Your APNS certificate has expired.
# Event::Mobile::ApnsCertificateRenewed	Your APNS certificate was renewed.
# Event::Mobile::ApnsCertificateRevoked	APNs certificate was revoked.
 
# Event::Mobile::UserEmailMissing	Please add the email address for user {1}.
# Event::Protection::CustomerHeartbeatCertificateRenewalFailure	The renewal of your Heartbeat intermediate certificate has failed.
# Event::Smc::MigrationActionsCancelled	Device actions have been cancelled, to turn on migration to the next mobile management version.
# Event::Smc::MigrationCancelled	Migration cancelled: Migration of your data to the next mobile management version was cancelled.
# Event::Smc::MigrationFailed	Migration failed: Migration of your data to the next mobile management version has failed.
# Event::Smc::MigrationPreventedByAdminEmail	Migrating your data to the next mobile management version has failed. The same email address {1} is used by admin accounts {2} and {3}.
# Event::Smc::MigrationStarted	Migration started: Your data is migrated to the next mobile management version.
# Event::Smc::MigrationSucceeded	Migration succeeded: Your data was migrated to the next mobile management version.
# Event::Smc::SynchronizationFailed	Synchronization of your data to the next mobile management version failed.
# Event::Smc::AfwNotEnrolled	Failed to communicate with a Google web service because you have removed Sophos Mobile as an EMM provider from your Android enterprise account.
# Event::Smc::AfwUnapprovedAppUsedInOtherObjectEvent	Unapproved Android work app ''{1}'' used in a task bundle
# Event::Smc::AfwClientConnectionError::1	Android Enterprise connection error (Unauthorized access. Make sure all required APIs are enabled.)
# Event::Smc::AfwClientConnectionError::2	Android Enterprise connection error (Error: ''{2}''. Description: ''{3}''.)
# Event::Smc::AfwRequiredAppNotApproved::1	Required app ''{2}'' ({1}) not approved in managed Google Play
# Event::Smc::DepRequiresAcceptingTermsOfUse	Apple DEP terms and conditions have not been accepted yet.
# Event::Smc::MitmAttackEvent::0	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}.
# Event::Smc::MitmAttackEvent::1	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}
# Event::Smc::MitmAttackEvent::2	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}, {5}
# Event::Smc::MitmAttackEvent::3	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}, {5}, {6}
# Event::Smc::MitmAttackEvent::4	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}, {5}, {6}, {7}
# Event::Smc::MitmAttackEvent::5	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}, {5}, {6}, {7}, {8}
# Event::Smc::MitmAttackEvent::6	Man in the middle attack detected in wifi {2} (bssid {3}) at {1}. Detected attacking types: {4}, {5}, {6}, {7}, {8}...
# Event::Smc::RenewSmcLicense::1	Your Sophos Mobile License will expire in {1} days
# Event::Smc::RenewSmcLicense::2	Your Sophos Mobile License will expire in 1 day.
# Event::Smc::RenewSmcLicense::3	Your Sophos Mobile License will expire in less than a day.
# Event::Smc::RenewAppleDepToken::1	Your Apple Dep Token will expire in {1} day/s.
# Event::Smc::RenewAppleDepToken::2	Your Apple Dep Token will expire in 1 day.
# Event::Smc::RenewAppleDepToken::3	Your Apple Dep Token will expire in less than a day.
# Event::Smc::RenewAppleVpp::1	Your Apple Vpp will expire in {1} days.
# Event::Smc::RenewAppleVpp::2	Your Apple Vpp will expire in 1 day.
# Event::Smc::RenewAppleVpp::3	Your Apple Vpp will expire in less than a day.
# Event::Smc::RenewKnoxLicense::1	Your Knox License will expire in {1} day/s.
# Event::Smc::RenewKnoxLicense::2	Your Knox License will expire in 1 day.
# Event::Smc::RenewKnoxLicense::3	Your Knox License will expire in less than a day.
# Event::Smc::RenewInstalledCertificate::1	Your configured certificate {3} from profile {2} will expire in {1} day/s.
# Event::Smc::RenewInstalledCertificate::2	Your configured certificate {2} from profile {1} will expire in 1 day.
# Event::Smc::RenewInstalledCertificate::3	Your configured certificate {2} from profile {1} will expire in less than a day.
# Event::Endpoint::Smc::WebFiltering::WARNED	"{1}'' warned due to {3} ''{4}''
# Event::Endpoint::Smc::WebFiltering::BLOCKED	 '{1}'' blocked due to {3} ''{4}''
# Event::Endpoint::Smc::WebFiltering::PROCEEDED	User bypassed {4} block to ''{1}''
# Event::SpamOrVirus::Alert	{1} reached threshold of {2} for {3} messages.
# Event::Xgemail::DlpViolationEvent	Data Loss Prevention {1} failed for target mailbox, {2}
# Event::Xgemail::DlpRuleDisableEvent	Email DLP error: rule "{1}" in policy "{2}" was turned off because it has a regular expression that ran for too long.
# Event::RateLimitAlert::Alert	Outbound sender rate limited for {1} 
# Event::OutboundMalwareProtection::EndpointScan	Endpoint scan has been initiated for {1}
# Event::OutboundMalwareProtection::BlockedSender	Sender {1} has been blocked for reaching the spam/virus threshold.
# Event::Endpoint::Smc::RenewInstalledCertificate::1	Your installed certificate {2} will expire in {1} day/s.
# Event::Endpoint::Smc::RenewInstalledCertificate::2	Your installed certificate {1} will expire in 1 day.
# Event::Endpoint::Smc::RenewInstalledCertificate::3	Your installed certificate {1} will expire in less than a day.
# Event::Endpoint::Smc::DeviceTemThresholdExceeded	The mobile device exceeded the mobile data volume threshold.
# Event::Endpoint::Smc::Uem::EnrollmentFailed	Can't enroll the UEM agent: {1}
# Event::Task::NoApnsCertificate	No APNS certificate configured
# Event::Endpoint::Mobile::Action::Cancelled	{1} cancelled
# Event::Endpoint::Mobile::Action::Skipped	{1} skipped
# Event::Endpoint::Mobile::Action::Failed	{1} failed
# Event::Endpoint::Mobile::Action::Succeeded	{1} succeeded
# Event::Endpoint::Threat::HIPSCleanupFailed::FULL_SCAN_REQUIRED	Computer scan required to complete running malware cleanup: {1}
# Event::Endpoint::Threat::HIPSCleanupFailed::CLEANUPABLE	Running malware not cleaned up: {1}
# Event::Endpoint::Threat::HIPSCleanupFailed::CLEANUP_IN_PROGRESS	Running malware not cleaned up: {1}
# Event::Endpoint::Threat::HIPSCleanupFailed::REBOOT_REQUIRED	Reboot required to complete running malware cleanup: {1}
# Event::Endpoint::Threat::HIPSCleanupFailed::NONE	Running malware requires manual cleanup: {1}
# Event::Endpoint::Threat::CleanupFailed::FULL_SCAN_REQUIRED	Computer scan required to complete cleanup: {1}
# Event::Endpoint::Threat::CleanupFailed::CLEANUPABLE	Malware not cleaned up: {1}
# Event::Endpoint::Threat::CleanupFailed::CLEANUP_IN_PROGRESS	Malware not cleaned up: {1}
# Event::Endpoint::Threat::CleanupFailed::REBOOT_REQUIRED	Reboot required to complete cleanup: {1}
# Event::Endpoint::Threat::CleanupFailed::NONE	Manual cleanup required: {1}
# Event::Endpoint::Threat::PuaCleanupFailed::FULL_SCAN_REQUIRED	Computer scan required to complete PUA cleanup: {1}
# Event::Endpoint::Threat::PuaCleanupFailed::CLEANUPABLE	PUA not cleaned up: {1}
# Event::Endpoint::Threat::PuaCleanupFailed::CLEANUP_IN_PROGRESS	PUA not cleaned up: {1}
# Event::Endpoint::Threat::PuaCleanupFailed::REBOOT_REQUIRED	Reboot required to complete PUA cleanup: {1}
# Event::Endpoint::Threat::PuaCleanupFailed::NONE	Manual PUA cleanup required: {1}
# Event::Task::MigrateUserDevicesToServers	User devices will be migrated to Server Protection.
# Event::Endpoint::Denc::EncryptionSuspendedEvent	Device Encryption is suspended.
# Event::Endpoint::Denc::OutlookPluginDisabledEvent	Outlook add-in is turned off.
# Event::Endpoint::Denc::OutlookPluginEnabledEvent	Outlook add-in is turned off.
# Event::Endpoint::Denc::PostponedAuthenticationResetEvent	The authentication reset request has been postponed five times by the user.
# Event::Endpoint::Denc::PostponedAuthenticationResetEvent::1	The authentication reset request has been postponed five times by the user for the volume with id: {1}.
# Event::Endpoint::Enc::DiskEncryptionFailed::1	Device Encryption failed on volume with id: {1}. Reason: {2}.
# Event::Endpoint::Enc::DiskEncryptionFailed::2	Device Encryption failed. Reason: {1}.
# Event::Endpoint::Enc::Recovery::KeyCreationFailed::1	Key creation failed for volume: {1}. Reason: {2}.
# Event::Endpoint::Enc::Recovery::KeyCreationFailed::2	Key creation failed. Reason: {1}.
# Event::Endpoint::Enc::Recovery::KeyReceived	A {1} recovery key has been received from: {2}.
# Event::Endpoint::Enc::Recovery::KeyRevoked	A {1} recovery key has been revoked from: {2}.
# Event::Endpoint::Enc::DiskEncryptionInformation::1	Device Encryption information for volume with id: {1}. Message: {2}.
# Event::Endpoint::Enc::DiskEncryptionInformation::2	Device Encryption information: {1}.
# Event::Endpoint::Enc::DiskNotEncryptedEvent	Device is not encrypted.
# Event::Endpoint::Enc::RecoveryKeyMissingEvent	A volume recovery key is missing.
# Event::Endpoint::Enc::RecoveryKeyMissingEvent::1	The recovery key for volume {1} is missing.
# Event::Endpoint::Enc::DiskEncryptionStatusChanged::2	The Device Encryption status changed from {1} to {2}.
# Event::Endpoint::Fenc::UserKeyringSyncedEvent::1	File Encryption keys have been synchronized for user {1}.
# Event::Wireless::AccessPoint::BadHealth	Access Point "{1}" has bad health.
# Event::Wireless::AccessPoint::NotBroadcast	Access Point "{1}" is not broadcasting any network.
# Event::Wireless::AccessPoint::Offline	Access Point "{1}" is offline.
# Event::Wireless::AccessPoint::CommandDone	Access Point "{1}" {2} done
# Event::Wireless::AccessPoint::ConfigurationFailed	Access Point "{1}" configuration failed
# Event::Wireless::AccessPoint::Firmware::UpdateStarted	Access Point "{1}" will be updated with new firmware "{2}"
# Event::Wireless::AccessPoint::Firmware::UpdateSucceeded	Access Point "{1}" has been successfully updated with new firmware "{2}". The update took {3} minutes.
# Event::Wireless::AccessPoint::Firmware::UpdateFailed	Access Point "{1}" failed to update to the new firmware "{2}". The update was tried for {3} minutes.
# Event::Wireless::AccessPoint::HighDataPacketRetries	Access Point "{1}" has high data packet retries ({5}%) on "{3}" Band, Channel "{4}"
# Event::Wireless::AccessPoint::HighDataPacketRetriesGhz24	Access Point "{1}" has high data packet retries on 2.4 GHZ Band.
# Event::Wireless::AccessPoint::HighDataPacketRetriesGhz5	Access Point "{1}" has high data packet retries on 5 GHZ Band.
# Event::Wireless::Firmware::Global::UpdateStarted	All Access Points will be updated with the new firmware version "{1}".
# Event::Wireless::Firmware::Global::UpdateSucceeded	All Access Points ({1}) have been successfully updated to firmware version "{2}". Firmware details are available
# Event::Wireless::Firmware::Global::UpdateFailed	Firmware update to version {1} failed after {2} minutes for {4} Access Points. The other {3} Access Points updated successfully. Firmware details are available 
# Event::Wireless::AccessPoint::DnsTimeout	Access Point "{1}" has a DNS timeout.
# Event::Wireless::AccessPoint::HighDnsLatency	Access Point "{1}" has high DNS latency ({2} ms).
# Event::Wireless::AccessPoint::ChannelChangedReason	Access Point "{1}" channel set to {3} for {2} band due to {4}
# Event::Wireless::AccessPoint::ChannelChanged	Access Point "{1}" channel has been changed.
# Event::Wireless::AccessPoint::LowEthernetSpeed	Access Point "{1}" low ethernet speed {2} Mbps detected.
# Event::Wireless::AccessPoint::HighEthernetSpeed	Access Point "{1}" ethernet speed {2} Mbps restored.
# Event::Wireless::AccessPoint::RadiusInactive	Access Point "{1}" radius server {2} : {3} is unreachable
# Event::Wireless::AccessPoint::RadiusActive	Access Point "{1}" radius server {2} : {3} is reachable
# Event::Wireless::AccessPoint::GatewayNotReachable	The gateway IP of access point "{1}" ({2}) was unreachable for more than {3} minute(s)
# Event::Wireless::AccessPoint::GnatHotspotVlanInvalidConfiguration	The access point "{1}" with gnat+hotspot+vlan has invalid configuration for VLAN {2}
# Event::Wireless::SyncSecurity::WrongConfig	Security Heartbeat with Endpoint is enabled for both Firewall and Central Wireless
# Event::Endpoint::Management::Resumed	Central management has been resumed.
# Event::Endpoint::Management::Suspended	Central management has been suspended.
# Event::Endpoint::DataLossPreventionAutomaticallyBlocked	A "block transfer" action was taken.
# Event::Endpoint::DataLossPreventionUserAllowed	An "allow transfer on acceptance by user" action was taken.
# Event::Endpoint::DataLossPreventionUserBlocked	A "block transfer on acceptance by user" action was taken.
# Event::Endpoint::DataLossPreventionAutomaticallyAllowed	An "allow file transfer" action was taken.
# Event::Endpoint::FileIntegrityMonitoring::Suspend	File Integrity Monitoring - processing has been suspended.
# Event::Endpoint::FileIntegrityMonitoring::Resume	File Integrity Monitoring - processing has been resumed.
# Event::UAV::Requested	Sent User Activity Verification question "{1}" to user.
# Event::UAV::Requested::QUESTION_MALICIOUS_COMMUNICATIONS	Sent User Activity Verification question "Sophos detected malicious communications from your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know."
# Event::UAV::Requested::QUESTION_UNUSUAL_ACTIVITY	Sent User Activity Verification question "Sophos detected unusual activity on your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know."
# Event::UAV::Responded	User responded to User Activity Verification question "{1}" with "{2}".
# Event::UAV::Responded::QUESTION_MALICIOUS_COMMUNICATIONS	User responded to User Activity Verification question "Sophos detected malicious communications from your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know." with "{3}".
# Event::UAV::Responded::QUESTION_UNUSUAL_ACTIVITY	User responded to User Activity Verification question "Sophos detected unusual activity on your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know." with "{3}"
# Event::UAV::TimedOut	User did not respond to User Activity Verification question "{1}" within {2} seconds.
# Event::UAV::TimedOut::QUESTION_MALICIOUS_COMMUNICATIONS	User did not respond to User Activity Verification question "Sophos detected malicious communications from your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know." within {3} seconds.
# Event::UAV::TimedOut::QUESTION_UNUSUAL_ACTIVITY	User did not respond to User Activity Verification question "Sophos detected unusual activity on your device {1} at {2} (UTC). You can help by providing further information. Select the statement that best describes what you know." within {3} seconds
# Event::UAV::PotentiallyCompromisedDevice	Device "{1}" is potentially compromised
# Event::ZTNA::ZTNAGatewayUnreachable	Gateway is disconnected
# Event::ZTNA::ZTNAApplicationUnreachable	Application is unreachable
# Event::ZTNA::ZTNAAuthenticationFailure	User has failed authen