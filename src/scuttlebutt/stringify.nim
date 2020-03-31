## Stringfy JSON like NodeJS does

import std/json, std/strutils, std/tables

proc nl2(s: var string, ml: bool) =
  s.add(if ml: "\n" else: " ")

proc newIndent(curr, indent: int, ml: bool): int =
  if ml: return curr + indent
  else: return indent

proc stringify(result: var string, node: json.JsonNode, indent = 2, ml = true,
              lstArr = false, currIndent = 0) =
  case node.kind
  of JObject:
    if lstArr: result = result.indent(currIndent) # Indentation
    if node.fields.len > 0:
      result.add("{")
      result.nl2(ml) # New line
      var i = 0
      for key, val in pairs(node.fields):
        if i > 0:
          result.add(",")
          result.nl2(ml) # New Line
        inc i
        # Need to indent more than {
        result = result.indent(newIndent(currIndent, indent, ml))
        escapeJson(key, result)
        result.add(": ")
        stringify(result, val, indent, ml, false,
                 newIndent(currIndent, indent, ml))
      result.nl2(ml)
      result = result.indent(currIndent) # indent the same as {
      result.add("}")
    else:
      result.add("{}")
  of JString:
    if lstArr: result = result.indent(currIndent)
    escapeJson(node.str, result)
  of JInt:
    if lstArr: result = result.indent(currIndent)
    when defined(js): result.add($node.num)
    else: result.add(node.num)
  of JFloat:
    if lstArr: result = result.indent(currIndent)
    # Fixme: implement new system.add ops for the JS target
    when defined(js): result.add($node.fnum)
    else: result.add(node.fnum)
  of JBool:
    if lstArr: result = result.indent(currIndent)
    result.add(if node.bval: "true" else: "false")
  of JArray:
    if lstArr: result = result.indent(currIndent)
    if len(node.elems) != 0:
      result.add("[")
      result.nl2(ml)
      for i in 0..len(node.elems)-1:
        if i > 0:
          result.add(",")
          result.nl2(ml) # New Line
        stringify(result, node.elems[i], indent, ml,
            true, newIndent(currIndent, indent, ml))
      result.nl2(ml)
      result = result.indent(currIndent)
      result.add("]")
    else: result.add("[]")
  of JNull:
    if lstArr: result = result.indent(currIndent)
    result.add("null")

proc stringify*(node: JsonNode, indent = 2): string =
  ## Returns a JSON Representation of `node`, with indentation and
  ## on multiple lines.
  result = ""
  stringify(result, node, indent)
