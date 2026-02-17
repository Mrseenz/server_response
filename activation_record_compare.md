# Activation Record Comparison

## Keyset
- Response keys: `AccountToken, AccountTokenCertificate, AccountTokenSignature, DeviceCertificate, FairPlayKeyData, RegulatoryInfo, UniqueDeviceCertificate, unbrick`
- Repo keys: `AccountToken, AccountTokenCertificate, AccountTokenSignature, DeviceCertificate, FairPlayKeyData, RegulatoryInfo, UniqueDeviceCertificate, unbrick`
- Same key set: **True**

## Field equality
- `AccountToken` equal: **False** (response_len=386, repo_len=1378)
- `AccountTokenCertificate` equal: **True** (response_len=1241, repo_len=1241)
- `AccountTokenSignature` equal: **True** (response_len=128, repo_len=128)
- `DeviceCertificate` equal: **True** (response_len=1082, repo_len=1082)
- `FairPlayKeyData` equal: **True** (response_len=1594, repo_len=1594)
- `RegulatoryInfo` equal: **False** (response_len=46, repo_len=46)
- `UniqueDeviceCertificate` equal: **True** (response_len=2118, repo_len=2118)
- `unbrick` equal: **True** (response_len=n/a, repo_len=n/a)
