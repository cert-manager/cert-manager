package pki

import "encoding/asn1"

// Puppet extensions
// ppRegCertExt range
var (
	// Puppet node Uuid
	ppUuid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 1}
	// Puppet node instance Id
	ppInstanceId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 2}
	// Puppet node image name
	ppImageName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 3}
	// Puppet node preshared key
	ppPresharedKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 4}
	// Puppet node cost center name
	ppCostCenter = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 5}
	// Puppet node product name
	ppProduct = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 6}
	// Puppet node project name
	ppProject = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 7}
	// Puppet node application name
	ppApplication = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 8}
	// Puppet node service name
	ppService = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 9}
	// Puppet node employee name
	ppEmployee = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 10}
	// Puppet node createdBy tag
	ppCreatedBy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 11}
	// Puppet node environment name
	ppEnvironment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 12}
	// Puppet node role name
	ppRole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 13}
	// Puppet node software version
	ppSoftwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 14}
	// Puppet node department name
	ppDepartment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 15}
	// Puppet node cluster name
	ppCluster = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 16}
	// Puppet node provisioner name
	ppProvisioner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 17}
	// Puppet node region name
	ppRegion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 18}
	// Puppet node datacenter name
	ppDatacenter = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 19}
	// Puppet node zone name
	ppZone = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 20}
	// Puppet node network name
	ppNetwork = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 21}
	// Puppet node security policy name
	ppSecuritypolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 22}
	// Puppet node cloud platform name
	ppCloudplatform = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 23}
	// Puppet node application tier
	ppApptier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 24}
	// Puppet node hostname
	ppHostname = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 25}
)

// ppAuthCertExt range
var (
	// Certificate extension authorization
	ppAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 1}
	// Puppet node role name for authorization. For Pe internal use only.
	ppAuthRole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 13}
)
