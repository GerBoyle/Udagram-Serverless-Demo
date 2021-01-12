import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJO//hsB64r2/RMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi10bmg1aTZ2cy5ldS5hdXRoMC5jb20wHhcNMjEwMTA2MDAxOTMxWhcN
MzQwOTE1MDAxOTMxWjAkMSIwIAYDVQQDExlkZXYtdG5oNWk2dnMuZXUuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyIN8DP6wBu4D8gzY
1Yng6nNorOp6SAo2iIE4QHu/dbY/eGx+o71GhUB58GW6IBXeNjenL3EAoV6eciWP
qdENhhnb0nEgbI/JMe/iiWNm6Qe3kWOMcox/axD4GNheAZ7sxGA1tshu32rRCTq9
UFp6jf7UGS2F9YNn8KYWFSWqEDO+s+h5mUnw1X8sijMKJBPH8Tt+RFzDzkbc+dxH
607ZJsEQ8rulN8p6Yur4Gt+r/fpGVwhG5GPjQBkO8vCqFmatYPHYx12wcgb0wqZ7
W8GGZA278Bo+kr0VefCN8V/9nbXljCSUePWZOxgB3D2EHjbnUIesEZ8KPRwX2BNY
X05XTwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ01+/0BjsN
Jn1GxYd53jrWclUW4zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
ALnjfjl1tu0hzbx+z+/PxhEuI0ta5W9R4XOEPAnLa4IlukaAvebXFISQ0q+xtGA8
T+LBQGPv5gv9w5Die4ctBq4p1hpkDfPckeuFvK/yPtbfI4fcDOSN/ZCD/nmi0EmV
ByzPOpgpuvYCLUi85+jREWIZccKtfHJTmpDMmkMcz11nVt5khXVBJCymLnCUJoe9
nABiiQdDYV+T2r3FSJnqYFtEf+/3MkuxNVgKbRNt0k14CQhuMug2q3zNXghdvidD
Z1XLkP6j/lWW3xy3/7OubYrd6/aa0JEjYbLGSOwxScN4u8QvIdIL0pL567Hyp1WM
zEVL3Ol4c1tqaIaeGzTJny8=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}