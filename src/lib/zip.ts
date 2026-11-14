// Reads uploaded source files in the browser: plain text files, or a .zip
// unpacked with the platform DecompressionStream. Nothing is uploaded.

export type SourceFile = { path: string; text: string; bytes: number }
export type Uploads = { files: SourceFile[]; skipped: number; totalBytes: number }

const MAX_FILES = 400
const MAX_FILE_BYTES = 1_500_000
const MAX_TOTAL_BYTES = 12_000_000
const SKIP_DIRS = /(^|\/)(node_modules|\.git|\.next|dist|build|out|vendor|coverage|\.cache|target|__pycache__)(\/|$)/i
const TEXT_EXT =
  /\.(m?[jt]sx?|cjs|css|scss|sass|less|html?|vue|svelte|astro|php|py|rb|go|rs|java|kt|kts|swift|cs|c|h|cpp|hpp|scala|clj|ex|exs|erl|hs|lua|pl|sh|bash|zsh|ps1|sql|graphql|gql|json|jsonc|ya?ml|toml|ini|env|cfg|conf|properties|xml|svg|md|txt|lock|tf|dockerfile|pem|p12)$/i
const SKIP_FILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|bun\.lockb|composer\.lock|Cargo\.lock|poetry\.lock)$/i

const decoder = new TextDecoder('utf-8', { fatal: false })

function looksBinary(bytes: Uint8Array) {
  const limit = Math.min(bytes.length, 512)
  for (let i = 0; i < limit; i++) if (bytes[i] === 0) return true
  return false
}

function isTextPath(path: string) {
  const base = path.split('/').pop() ?? path
  return TEXT_EXT.test(base) || /^(\.env|Dockerfile|Makefile|Procfile)/i.test(base)
}

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') throw new Error('This browser cannot open zip files. Upload the files instead.')
  const stream = new Blob([data as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate-raw'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

/** Minimal ZIP reader: central directory only, stored (0) and deflate (8). */
async function readZip(buffer: ArrayBuffer): Promise<{ path: string; text: string; bytes: number }[]> {
  const view = new DataView(buffer)
  const bytes = new Uint8Array(buffer)
  let eocd = -1
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65_557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new Error('That file is not a valid zip archive.')

  const count = view.getUint16(eocd + 10, true)
  let offset = view.getUint32(eocd + 16, true)
  const out: { path: string; text: string; bytes: number }[] = []
  const nameBytes = new TextDecoder()

  for (let i = 0; i < count && i < MAX_FILES * 2; i++) {
    if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) break
    const method = view.getUint16(offset + 10, true)
    const compressedSize = view.getUint32(offset + 20, true)
    const uncompressedSize = view.getUint32(offset + 24, true)
    const nameLen = view.getUint16(offset + 28, true)
    const extraLen = view.getUint16(offset + 30, true)
    const commentLen = view.getUint16(offset + 32, true)
    const localOffset = view.getUint32(offset + 42, true)
    const path = nameBytes.decode(bytes.subarray(offset + 46, offset + 46 + nameLen))
    offset += 46 + nameLen + extraLen + commentLen

    if (path.endsWith('/') || SKIP_DIRS.test(path) || SKIP_FILES.test(path) || !isTextPath(path)) continue
    if (uncompressedSize > MAX_FILE_BYTES || out.length >= MAX_FILES) continue

    if (localOffset + 30 > bytes.length || view.getUint32(localOffset, true) !== 0x04034b50) continue
    const localNameLen = view.getUint16(localOffset + 26, true)
    const localExtraLen = view.getUint16(localOffset + 28, true)
    const start = localOffset + 30 + localNameLen + localExtraLen
    const data = bytes.subarray(start, start + compressedSize)
    if (!data.length) continue

    try {
      const raw = method === 0 ? data : method === 8 ? await inflateRaw(data) : null
      if (!raw || looksBinary(raw)) continue
      out.push({ path, text: decoder.decode(raw), bytes: raw.length })
    } catch {
      // A single unreadable entry should never fail the whole archive.
    }
  }
  return out
}

async function readTextFile(file: File): Promise<SourceFile | null> {
  if (file.size > MAX_FILE_BYTES) return null
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)
  if (looksBinary(bytes)) return null
  return { path: file.name, text: decoder.decode(bytes), bytes: bytes.length }
}

export async function readUploads(input: File[]): Promise<Uploads> {
  const files: SourceFile[] = []
  let skipped = 0
  let totalBytes = 0

  for (const file of input) {
    if (files.length >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) {
      skipped += 1
      continue
    }
    const isZip = /\.zip$/i.test(file.name) || file.type === 'application/zip' || file.type === 'application/x-zip-compressed'
    if (isZip) {
      if (file.size > 24_000_000) {
        skipped += 1
        continue
      }
      try {
        const entries = await readZip(await file.arrayBuffer())
        if (!entries.length) skipped += 1
        for (const entry of entries) {
          if (files.length >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) {
            skipped += 1
            continue
          }
          files.push({ path: `${file.name}/${entry.path}`, text: entry.text, bytes: entry.bytes })
          totalBytes += entry.bytes
        }
      } catch {
        skipped += 1
      }
      continue
    }
    if (SKIP_DIRS.test(file.name) || SKIP_FILES.test(file.name) || !isTextPath(file.name)) {
      skipped += 1
      continue
    }
    const read = await readTextFile(file)
    if (!read) {
      skipped += 1
      continue
    }
    files.push(read)
    totalBytes += read.bytes
  }

  return { files, skipped, totalBytes }
}
