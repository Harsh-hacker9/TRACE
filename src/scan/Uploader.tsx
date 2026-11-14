import { FileCode2, FolderOpen, Upload, X } from 'lucide-react'
import { useRef, useState } from 'react'

import { Button } from '@/components/Button'
import { IconButton } from '@/components/IconButton'
import { cn } from '@/lib/cn'

const formatBytes = (bytes: number) => (bytes >= 1_048_576 ? `${(bytes / 1_048_576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`)

export function Uploader({
  files,
  onFiles,
  onScan,
  busy,
}: {
  files: File[]
  onFiles: (files: File[]) => void
  onScan: () => void
  busy: boolean
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  const add = (list: FileList | null) => {
    if (!list?.length) return
    const merged = [...files]
    for (const file of Array.from(list)) {
      if (!merged.some((existing) => existing.name === file.name && existing.size === file.size)) merged.push(file)
    }
    onFiles(merged.slice(0, 80))
  }

  return (
    <div className="p-4">
      <div
        onDragOver={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault()
          setDragging(false)
          add(event.dataTransfer.files)
        }}
        className={cn(
          'flex flex-col items-center border border-dashed px-5 py-10 text-center transition-colors duration-150',
          dragging ? 'border-line-strong bg-surface-2' : 'border-line',
        )}
      >
        <span className="flex size-10 items-center justify-center border border-line-strong text-fg">
          <Upload className="size-4" aria-hidden />
        </span>
        <p className="mt-4 text-[15px] font-medium">Drop your project here, or a .zip of it</p>
        <p className="mt-1.5 max-w-sm text-[13px] leading-relaxed text-muted">
          Source and config files only. node_modules, build output and lockfiles are skipped automatically.
        </p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => inputRef.current?.click()} icon={<FolderOpen className="size-4" />}>
          Choose files
        </Button>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="sr-only"
          aria-label="Choose source files or a zip"
          onChange={(event) => {
            add(event.target.files)
            event.target.value = ''
          }}
        />
      </div>

      {files.length > 0 && (
        <ul className="mt-3 max-h-56 overflow-y-auto border border-line">
          {files.map((file, index) => (
            <li key={`${file.name}-${file.size}-${index}`} className="flex items-center gap-2.5 border-b border-line px-3 py-2 last:border-0">
              <FileCode2 className="size-4 shrink-0 text-muted" aria-hidden />
              <span className="min-w-0 flex-1 truncate font-mono text-[11.5px]">{file.name}</span>
              <span className="shrink-0 font-mono text-[11px] text-muted">{formatBytes(file.size)}</span>
              <IconButton label={`Remove ${file.name}`} size="sm" onClick={() => onFiles(files.filter((_, i) => i !== index))}>
                <X className="size-3.5" />
              </IconButton>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <p className="font-mono text-[11px] text-muted">Read in this tab. Nothing is uploaded.</p>
        <Button variant="primary" onClick={onScan} loading={busy} disabled={!files.length || busy}>
          Scan {files.length === 1 ? 'file' : `${files.length || ''} files`}
        </Button>
      </div>
    </div>
  )
}
