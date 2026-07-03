const decoder = new TextDecoder()
const encoder = new TextEncoder()

export function textToBase64(value: string): string {
  let binary = ''
  for (const byte of encoder.encode(value)) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function base64ToText(value?: string): string {
  const binary = atob(value || '')
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return decoder.decode(bytes, { stream: true })
}
