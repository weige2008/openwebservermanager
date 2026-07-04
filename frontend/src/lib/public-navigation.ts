export function resolvePublicHref(href: string) {
  if (href.startsWith('#')) return `/${href}`
  return href
}
