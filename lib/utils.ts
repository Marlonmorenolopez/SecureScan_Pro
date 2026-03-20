export function cn(...inputs: Array<string | null | undefined | false>) {
  const classes = inputs.filter(Boolean).join(' ')
  return Array.from(new Set(classes.split(/\s+/))).join(' ')
}