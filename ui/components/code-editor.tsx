"use client"

import { useEffect, useRef } from "react"
import { basicSetup } from "codemirror"
import { Compartment, EditorState } from "@codemirror/state"
import { EditorView } from "@codemirror/view"
import { StreamLanguage } from "@codemirror/language"
import { setDiagnostics, type Diagnostic } from "@codemirror/lint"
import { rego } from "@/lib/rego-language"

export interface EditorProblem {
  row?: number
  col?: number
  message: string
}

interface CodeEditorProps {
  value: string
  onChange?: (value: string) => void
  language?: "rego" | "json" | "text"
  readOnly?: boolean
  // problems are shown inline; rows and columns are 1-based.
  problems?: EditorProblem[]
  ariaLabel: string
  className?: string
}

const json = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null
    if (stream.match(/^"(?:[^"\\]|\\.)*"\s*(?=:)/)) return "propertyName"
    if (stream.match(/^"(?:[^"\\]|\\.)*"?/)) return "string"
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return "number"
    if (stream.match(/^(true|false|null)\b/)) return "atom"
    stream.next()
    return null
  },
})

const theme = EditorView.theme({
  "&": { height: "100%", fontSize: "13px", backgroundColor: "transparent" },
  ".cm-scroller": { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" },
  ".cm-gutters": { backgroundColor: "transparent", borderRight: "1px solid hsl(var(--border))", color: "hsl(var(--muted-foreground))" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "hsl(var(--muted) / 0.5)" },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { caretColor: "hsl(var(--foreground))" },
})

// CodeEditor is a CodeMirror editor; value is controlled, so a new value
// from outside (another file, a formatted result) replaces the document.
export function CodeEditor({ value, onChange, language = "text", readOnly = false, problems, ariaLabel, className }: CodeEditorProps) {
  const host = useRef<HTMLDivElement>(null)
  const view = useRef<EditorView | null>(null)
  const onChangeRef = useRef(onChange)
  const editable = useRef(new Compartment())
  onChangeRef.current = onChange

  useEffect(() => {
    if (!host.current) return
    const lang = language === "rego" ? [rego] : language === "json" ? [json] : []
    const v = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          basicSetup,
          theme,
          ...lang,
          editable.current.of([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
          EditorView.contentAttributes.of({ "aria-label": ariaLabel }),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) onChangeRef.current?.(u.state.doc.toString())
          }),
        ],
      }),
    })
    view.current = v
    return () => {
      v.destroy()
      view.current = null
    }
    // The editor is created once per language; value and readOnly are synced below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [language, ariaLabel])

  useEffect(() => {
    const v = view.current
    if (!v) return
    const current = v.state.doc.toString()
    if (current !== value) v.dispatch({ changes: { from: 0, to: current.length, insert: value } })
  }, [value])

  useEffect(() => {
    view.current?.dispatch({
      effects: editable.current.reconfigure([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
    })
  }, [readOnly])

  useEffect(() => {
    const v = view.current
    if (!v) return
    const doc = v.state.doc
    const diagnostics: Diagnostic[] = (problems ?? []).map((p) => {
      const line = doc.line(Math.min(Math.max(p.row ?? 1, 1), doc.lines))
      const from = Math.min(line.from + Math.max((p.col ?? 1) - 1, 0), line.to)
      return { from, to: Math.max(from, line.to), severity: "error", message: p.message }
    })
    v.dispatch(setDiagnostics(v.state, diagnostics))
  }, [problems, value])

  return <div ref={host} className={className} />
}
