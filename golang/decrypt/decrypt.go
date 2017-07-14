package paperdecryptdata

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

const privateKeyData = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA7ivyNPVrRjJqKaOBL/UVESur+XCdAQ75Uicpxt0tOIuy2W8p
Ej5iBScL5WdE9R6fZcvPIPB7IR4N6eSu7FYEjJLqR4+Uvr6rUtdLIoadFymAZ5Zb
x2Og9MQHV5qTuj2ZAek97dK3ThsYIy0Mu7vj8ny81d8p+Yk6s0COHHtk16dZN0Td
gmReH5ghcfgjdx8OfpxrhsOp/UqvC1iuMedyzZ49n9p9FSJ20I8NYzT/UgevApGs
nTdLE7knRU+jZNuly22SBwVqMltPJgND1X+cmebsU8BKpwURyTuye3V6ssAG3DG5
T2hBJDTZR4TU/ziwPh1UaOrABiHNMtRdLbwY+QIDAQABAoIBACmbgcegrCnqOsOl
bbcsEI8cWwHLm5IIxKOGdfToxLKhLRBxK/Kk9UjDJn/gB5ruy5fj//5YJJqHfpTC
v5BIAqlwLP9tZOXht1pUhCq265CVTnpKOSRfEkpQSJwURASAKE++KHR4oE9Dynay
swvE6jB9fBu8zb9rKtcPywPMxrQpkNJsQGv5kHATl0IhZ4uT/1082zgOkZgI/P7z
Yjgws4nBAmmX7QGR/IR2doDePEAddv/GFQ5jbKz8ASvCGilQZu3ZcttDIn/OBexB
O2ueCysWc2B3kbW1Z/qVw8wrRP2sdrhC1/yRYtwtEtBOQekjiGf8PEiXXTZCVxq/
KXaPEIUCgYEA+tEvHtdXdK7TLcFZxhROLnhH4RsqAsmb/NCwl17BTAktl5QNLUGv
tK5ExD4OPhmF0eXHEUsgxS3l3X7cnCkoi77F6OU+O9uC/OLJJ2KhmVt5a5XPplaA
VkDDMT3NocPD2vUPwm/qdGlyLJpPomudC9kyZMlEzSKDN6yK42CS1rMCgYEA8xfe
Lv/5YeEx56TjG1W5IUnUiqsQDqus+UppdHSt/qStMiP87N8qQ+ERAAU6I2VSuemV
y88dUa2NYyMDhURzwBbjKtObiiDmo0oFXv7aX25rv5kMEts3FUlU6+ZQ3QEb3oVc
rR7UO+nUbbmBFSoPB7S00ZkVD2gXHm7evyVnh6MCgYEA6eHWRrQXYT8EvU3nIMYe
gUa4ADkMW70UMBOKGBzLstN8KDRudR0jcyBuD3CuZ0n1d10E3CNqU3QRPRHnNddL
b8RdWGcsOTTgWGBBovBeMFsURjZUg4917PhHC8vNzGJ4Z9zM7UrfHd6WEPF0AMjI
kRvf2gu0lHTyVyAWAyEyy/ECgYEAycpsU1OFLi0DgiirpUs5jFp/JkTt5V+5DI8q
jtM0hAcrBk49bFur+ADiXcP5CNzZGR6/jBl3Ww/YKA0upPe3piLZm/lgSf8ZtT6C
yuJ/X2yH4Noo3ZY/WVowNkpPocWD3umRjtvijYGDJzov3uO06k6lMsACbXGYj1i1
arKgCEUCgYEAub3Axfzk1mje759TEa2X+5qk/rdW+WVQfusYi5GQxxNkmAodLKYT
/G4o3tRv1oXV705D7wDFCbLX8JlWLnsaFAIVpFLngYziAfGPcIdPUVOrKMiivxrl
mkG81pqWAiQGVf6Hv+qvvYMUO9CX8tUp11r2zJ1LBqEFwFeqmPMUwOE=
-----END RSA PRIVATE KEY-----
`

// Decrypt func
func Decrypt(encryptData string) map[string]interface{} {
	hash := sha1.New()
	random := rand.Reader

	privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))
	priv, _ := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)

	ciphertext, _ := base64.StdEncoding.DecodeString(encryptData)

	decryptedData, _ := rsa.DecryptOAEP(hash, random, priv, ciphertext, nil)

	var dataDecrypted map[string]interface{}
	json.Unmarshal(decryptedData, &dataDecrypted)

	return dataDecrypted
}
