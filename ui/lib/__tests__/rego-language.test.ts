import { describe, it, expect } from "vitest"
import { StringStream } from "@codemirror/language"
import { regoParser } from "../rego-language"

// tokens runs the tokenizer over one line and returns [text, style] pairs.
function tokens(line: string): [string, string | null][] {
  const state = regoParser.startState!(2)
  const stream = new StringStream(line, 2, 2)
  const out: [string, string | null][] = []
  while (!stream.eol()) {
    const style = regoParser.token(stream, state)
    const text = stream.current()
    if (text.trim()) out.push([text, style])
    stream.start = stream.pos
  }
  return out
}

describe("rego tokenizer", () => {
  it("highlights keywords, strings, numbers and comments", () => {
    expect(tokens('allow if input.user == "ada" # admins')).toEqual([
      ["allow", "variableName"], ["if", "keyword"], ["input", "variableName.special"], [".", null], ["user", "variableName"],
      ["==", "operator"], ['"ada"', "string"], ["# admins", "comment"],
    ])
    expect(tokens("default limit := 10")).toEqual([["default", "keyword"], ["limit", "variableName"], [":=", "operator"], ["10", "number"]])
    expect(tokens("x := count(xs)")[2]).toEqual(["count", "function"])
  })

  it("handles escaped quotes and raw strings", () => {
    expect(tokens('m := "say \\"hi\\""')[2]).toEqual(['"say \\"hi\\""', "string"])
    expect(tokens("p := `C:\\path`")[2]).toEqual(["`", "string"])
  })
})
