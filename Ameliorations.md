# Soaphound Improvements - Enriched Information Retrieval for BloodHound

## Summary of Improvements

This document describes the improvements made to Soaphound to retrieve more information from Active Directory and format it correctly for BloodHound/Neo4j.

## 1. User Attributes Enrichment

### New Collected Attributes:
- `userPassword`, `unicodePwd`, `unixUserPassword`, `msSFU30Password` - To detect accounts with stored passwords
- `homeDirectory`, `scriptPath`, `profilePath`, `logonScript` - To analyze network paths and scripts
- `msDS-UserPasswordExpiryTimeComputed` - To determine password expiration
- `msDS-SupportedEncryptionTypes` - To identify supported encryption types
- `accountExpires` - To detect temporary accounts

### New Security Properties:
- `sensitive` - Account marked as sensitive (cannot be delegated)
- `dontreqpreauth` - Account vulnerable to AS-REP Roasting
- `passwordnotreqd` - Account with no password requirement
- `trustedtoauth` - Account authorized for constrained delegation with protocol transition
- `pwdneverexpires` - Password that never expires

**Impact**: Allows quick identification of vulnerable accounts and risky configurations in the AD environment.

## 2. Computer Attributes Enrichment

### New Collected Attributes:
- `serverReferenceBL` - To identify Domain Controllers
- `msDS-SupportedEncryptionTypes` - Supported encryption types
- `ms-DS-MachineAccountQuota` - Machine account quota
- `operatingSystemServicePack` - Detailed service pack
- `msDS-Cached-Membership`, `msDS-Cached-Membership-Time-Stamp` - Membership cache information

**Impact**: Better visibility into the configuration and role of computers in the domain.

## 3. SPN (Service Principal Names) Parsing

### New Feature: SPNTargets
A new `parse_spn_targets()` function parses ServicePrincipalName to create valid `SPNTargets` relationships in BloodHound.

**Output Format**:
```json
{
  "SPNTargets": [
    {
      "ObjectIdentifier": "S-1-5-21-xxx-yyy-zzz-1234",
      "ObjectType": "Computer"
    }
  ]
}
```

**Impact**: BloodHound can now visualize Kerberos delegation relationships between users/computers and target services.

## 4. msDS-AllowedToDelegateTo Parsing

### New Feature: AllowedToDelegate
A new `parse_allowed_to_delegate()` function correctly parses the `msDS-AllowedToDelegateTo` attribute to identify constrained delegation targets.

**What is Parsed**:
- Delegation SPNs in `service/hostname[:port]` format
- Hostname resolution to ObjectIdentifier (SID or GUID)
- Object type determination (User, Computer, Group)

**Output Format**:
```json
{
  "AllowedToDelegate": [
    {
      "ObjectIdentifier": "S-1-5-21-xxx-yyy-zzz-5678",
      "ObjectType": "Computer"
    }
  ]
}
```

**Impact**: Precise identification of attack paths via Kerberos constrained delegation.

## 5. Certificate Templates Collection (PKI)

### New Collector: certtemplates.py
A brand new collector for Active Directory Certificate Services (AD CS) certificate templates.

**Collected Attributes**:
- Enrollment flags (`enrollmentflag`, `certificatenameflag`)
- Certificate policies (`pKIExtendedKeyUsage`, `certificateapplicationpolicy`)
- Security configuration (`requiresmanagerapproval`, `authorizedsignatures`)
- Schema version and metadata

**Parsed Properties**:
- `requiresmanagerapproval` - Whether manager approval is required
- `effectiveekus` - Effective Extended Key Usages
- `schemaversion` - Template schema version
- `validityperiod`, `renewalperiod` - Validity and renewal periods

**Impact**: Identification of AD CS vulnerabilities (ESC1-ESC10) and certificate-based attack paths.

## 6. ACL Improvements

All formatting functions now include:
- Correct nTSecurityDescriptor parsing
- `IsACLProtected` detection
- Well-known SID prefixing with domain
- ACE deduplication

## Usage

Improvements are automatically enabled when running Soaphound:

```bash
python soaphound.py -u username -p password -d domain.local -dc dc01.domain.local
```

### Newly Generated Files:
- `{timestamp}_certtemplates.json` - PKI certificate templates

### Enriched Existing Files:
- `{timestamp}_users.json` - Users with extended properties
- `{timestamp}_computers.json` - Computers with extended properties and SPNTargets

## BloodHound Compatibility

All improvements are compatible with:
- BloodHound CE (Community Edition) v5+
- BloodHound Legacy v4.x
- Neo4j 4.x and 5.x

JSON formats strictly follow the BloodHound v6 schema.

## Security Analysis Benefits

### Improved Vulnerability Detection:
1. **Kerberoasting** - Identification via `hasspn` and `serviceprincipalnames`
2. **AS-REP Roasting** - Detection via `dontreqpreauth`
3. **Unconstrained Delegation** - Via `unconstraineddelegation`
4. **Constrained Delegation** - Via correctly parsed `AllowedToDelegate`
5. **RBCD (Resource-Based Constrained Delegation)** - Via `AllowedToAct`
6. **AD CS Attacks** - Via Certificate Templates
7. **Sensitive Accounts** - Via `sensitive`, `admincount`, `highvalue`
8. **Weak Passwords** - Via `passwordnotreqd`, `pwdneverexpires`

## Technical Architecture

### Modified Files:
- `src/soaphound/ad/collectors/user.py` - User enrichment + SPN parsing
- `src/soaphound/ad/collectors/computer.py` - Computer enrichment + delegation parsing
- `src/soaphound/ad/collectors/computer_adws.py` - Same for ADWS-only mode
- `src/soaphound/soaphound.py` - New collector integration

### New Files:
- `src/soaphound/ad/collectors/certtemplates.py` - PKI templates collector

### Added Helper Functions:
- `parse_spn_targets()` - SPN to SPNTargets parsing
- `parse_allowed_to_delegate()` - msDS-AllowedToDelegateTo parsing

## Recommended Tests

After installation, verify:
1. Presence of `SPNTargets` in users.json and computers.json
2. Presence of populated `AllowedToDelegate` for accounts with delegation
3. Generation of certtemplates.json file
4. `sensitive`, `dontreqpreauth` properties in users.json
5. Correct import into BloodHound without errors

