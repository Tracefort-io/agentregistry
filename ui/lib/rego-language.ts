import { StreamLanguage, type StreamParser } from "@codemirror/language"

// A small Rego tokenizer for syntax highlighting; the registry checks the
// real syntax.
const keywords = new Set([
  "package", "import", "as", "default", "if", "contains", "in", "every", "some", "not", "with", "else",
])
const atoms = new Set(["true", "false", "null"])
const builtins = new Set(["input", "data"])

interface State {
  inRawString: boolean
}

export const regoParser: StreamParser<State> = {
  name: "rego",
  startState: () => ({ inRawString: false }),
  token(stream, state) {
    if (state.inRawString) {
      if (stream.skipTo("`")) {
        stream.next()
        state.inRawString = false
      } else {
        stream.skipToEnd()
      }
      return "string"
    }
    if (stream.eatSpace()) return null
    if (stream.match("#")) {
      stream.skipToEnd()
      return "comment"
    }
    if (stream.match("`")) {
      state.inRawString = true
      return "string"
    }
    if (stream.match('"')) {
      let escaped = false
      let ch: string | void
      while ((ch = stream.next()) != null) {
        if (ch === '"' && !escaped) break
        escaped = !escaped && ch === "\\"
      }
      return "string"
    }
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return "number"
    if (stream.match(/^(:=|==|!=|<=|>=|=|<|>|\||&|\+|-|\*|\/|%)/)) return "operator"
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_]*/)) {
      const word = stream.current()
      if (keywords.has(word)) return "keyword"
      if (atoms.has(word)) return "atom"
      if (builtins.has(word)) return "variableName.special"
      if (stream.peek() === "(") return "function"
      return "variableName"
    }
    stream.next()
    return null
  },
  languageData: { commentTokens: { line: "#" } },
}

export const rego = StreamLanguage.define(regoParser)
