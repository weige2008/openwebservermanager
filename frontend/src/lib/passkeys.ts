export interface PasskeyCredentialDescriptor {
  type: PublicKeyCredentialType
  id: string
  transports?: AuthenticatorTransport[]
}

export interface PasskeyCreationPublicKeyOptions {
  challenge: string
  rp: PublicKeyCredentialRpEntity
  user: {
    id: string
    name: string
    displayName: string
  }
  pubKeyCredParams: PublicKeyCredentialParameters[]
  timeout?: number
  authenticatorSelection?: AuthenticatorSelectionCriteria
  attestation?: AttestationConveyancePreference
  excludeCredentials?: PasskeyCredentialDescriptor[]
}

export interface PasskeyRequestPublicKeyOptions {
  challenge: string
  timeout?: number
  rpId?: string
  allowCredentials?: PasskeyCredentialDescriptor[]
  userVerification?: UserVerificationRequirement
}

export interface PasskeyOptionsResponse<T> {
  challenge_id: string
  publicKey: T
}

export function passkeySupported() {
  return typeof window !== 'undefined' && Boolean(window.PublicKeyCredential)
}

export function passkeySecureContext() {
  return typeof window !== 'undefined' && window.isSecureContext
}

export function decodePasskeyCreationOptions(publicKey: PasskeyCreationPublicKeyOptions): PublicKeyCredentialCreationOptions {
  return {
    ...publicKey,
    challenge: base64URLToBuffer(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64URLToBuffer(publicKey.user.id),
    },
    pubKeyCredParams: publicKey.pubKeyCredParams.map((item) => ({
      ...item,
      type: item.type as PublicKeyCredentialType,
    })),
    excludeCredentials: publicKey.excludeCredentials?.map((item) => ({
      ...item,
      id: base64URLToBuffer(item.id),
      type: item.type as PublicKeyCredentialType,
    })),
  }
}

export function decodePasskeyRequestOptions(publicKey: PasskeyRequestPublicKeyOptions): PublicKeyCredentialRequestOptions {
  return {
    ...publicKey,
    challenge: base64URLToBuffer(publicKey.challenge),
    allowCredentials: publicKey.allowCredentials?.map((item) => ({
      ...item,
      id: base64URLToBuffer(item.id),
      type: item.type as PublicKeyCredentialType,
    })),
  }
}

export function passkeyAttestationPayload(credential: PublicKeyCredential, challengeID: string, name: string) {
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    challenge_id: challengeID,
    id: credential.id,
    raw_id: bufferToBase64URL(credential.rawId),
    type: credential.type,
    name,
    response: {
      client_data_json: bufferToBase64URL(response.clientDataJSON),
      attestation_object: bufferToBase64URL(response.attestationObject),
    },
  }
}

export function passkeyAssertionPayload(credential: PublicKeyCredential, challengeID: string) {
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    challenge_id: challengeID,
    id: credential.id,
    raw_id: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
      client_data_json: bufferToBase64URL(response.clientDataJSON),
      authenticator_data: bufferToBase64URL(response.authenticatorData),
      signature: bufferToBase64URL(response.signature),
      user_handle: response.userHandle ? bufferToBase64URL(response.userHandle) : '',
    },
  }
}

function base64URLToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=')
  const binary = window.atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes.buffer
}

function bufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index])
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}
