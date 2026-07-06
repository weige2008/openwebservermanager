export async function copyText(text: string) {
  const clipboardWrite = navigator.clipboard?.writeText
  if (clipboardWrite) {
    try {
      await clipboardWrite.call(navigator.clipboard, text)
      return
    } catch {
      // HTTP deployments and strict browser settings can expose the API but reject writes.
    }
  }

  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', 'true')
  textarea.style.position = 'fixed'
  textarea.style.top = '-1000px'
  textarea.style.left = '-1000px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  try {
    const copied = document.execCommand('copy')
    if (!copied) throw new Error('copy command failed')
  } finally {
    textarea.remove()
  }
}
