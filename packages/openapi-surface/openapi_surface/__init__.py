"""Derive attacker-writable strings and query parameters from OpenAPI.

Shared by Flask/SpecTree and FastAPI callers without framework dependencies.
Route ids use OpenAPI path form, e.g. ``POST /conversation/{conversation_id}``.
"""

from __future__ import annotations

from typing import Any

#: ``None`` covers untyped schemas, which accept a string.
_STRINGY = {"string", None}

_READ_METHODS = {"get", "head", "options"}


def _resolve(schema: dict, doc: dict) -> dict:
    ref = schema.get("$ref")
    if not ref or not ref.startswith("#/"):
        return schema
    node: Any = doc
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _walk(schema: dict, doc: dict, prefix: str, seen: frozenset[int]) -> list[str]:
    """Collect the dotted paths of every string field reachable from `schema`.

    `prefix` is the dotted path (already carrying any trailing ``[]``) that
    names `schema` itself; the empty string names the request body's root
    schema, which has no name of its own and therefore can never be reported
    as a leaf.

    Leaf detection happens exactly once, at the bottom of this function,
    after every structural key has been considered -- `allOf`/`anyOf`/`oneOf`,
    `type: array`, and `properties`. This matters because SpecTree renders
    `Optional[Model]` as ``{"anyOf": [Model, {"type": "null"}]}``: the
    property's own top-level dict then carries neither `type` nor
    `properties` (both live one level down, inside the `anyOf` branches), so
    a leaf check performed by the *caller* -- before recursing -- sees an
    untyped dict with no properties and wrongly concludes "string". The bug
    this fixed was exactly that: the array-items branch and the properties
    loop each ran their own copy of that premature check, so a
    `$ref`/combinator-wrapped submodel was reported as a scalar and its
    fields silently dropped from the attack surface. Centralising the
    decision here means both call sites just recurse and let this function
    decide, after looking at everything a schema can put between itself and
    "actually just a string".

    Cycle detection is sound with a single per-path immutable `seen` rather
    than a shared mutable set: each recursive call takes `seen | {ident}`
    and passes that copy on to its own children, so sibling branches -- two
    properties that `$ref` the same schema, or two `anyOf` branches -- do
    not see each other's visited nodes and each expands the shared schema in
    full. The only thing `seen` has to rule out is a schema revisiting one of
    its own ancestors on the path from the root, which is exactly what a
    cycle is. `id()` is a safe key for that because every schema handed to
    this function is either a literal node inside `doc` or the dict `_resolve`
    returns for a `$ref` (which is also a node inside `doc`, looked up by
    address, not copied) -- nothing here constructs a fresh dict for a schema
    fragment mid-walk, so no address is freed and reused while the walk of a
    single path is in progress.
    """
    schema = _resolve(schema, doc)
    ident = id(schema)
    if ident in seen:  # $ref cycles are legal and SpecTree emits them
        return []
    seen = seen | {ident}
    out: list[str] = []
    structural = False  # did this schema turn out to be a container, not a leaf?

    for combinator in ("allOf", "anyOf", "oneOf"):
        if combinator in schema:
            structural = True
            for sub in schema[combinator]:
                out += _walk(sub, doc, prefix, seen)

    if schema.get("type") == "array":
        structural = True
        out += _walk(schema.get("items", {}), doc, f"{prefix}[]", seen)

    # `additionalProperties` is deliberately not descended, and that is a
    # decision rather than an omission. A field typed `dict[str, str]` renders
    # as `{"type": "object", "additionalProperties": {"type": "string"}}`, whose
    # string leaves have no fixed names -- there is no dotted path to report,
    # because the attacker chooses the keys as well as the values. Reporting
    # the parent (`meta`) would be wrong too: `_plant` would then write a bare
    # string where the schema declares an object and SpecTree would 422 every
    # payload, which is the "route reported as seeded while nothing was
    # attacked" failure this module exists to avoid. Nothing in
    # server/schemas/ declares such a field today (every free-form field there
    # is `Any`, which this walk already reports as a string leaf), so the right
    # time to design a representation -- `meta.*`, say, with `_plant` inventing
    # a key -- is when the first one appears. Until then, silence here is
    # correct and this comment is what keeps it from being mistaken for a bug.
    if "properties" in schema:
        structural = True
        for name, sub in schema["properties"].items():
            path = f"{prefix}.{name}" if prefix else name
            out += _walk(sub, doc, path, seen)

    if not structural and prefix and schema.get("type") in _STRINGY:
        out.append(prefix)

    return out


def writable_string_fields(openapi: dict) -> dict[str, list[str]]:
    """Map route ids, e.g. ``"POST /conversation/{conversation_id}"``, to the
    dotted paths of their string fields."""
    result: dict[str, list[str]] = {}
    for path, operations in (openapi.get("paths") or {}).items():
        for method, operation in operations.items():
            if method.lower() in _READ_METHODS or not isinstance(operation, dict):
                continue
            content = (
                (operation.get("requestBody") or {}).get("content") or {}
            ).get("application/json") or {}
            fields = sorted(set(_walk(content.get("schema", {}), openapi, "", frozenset())))
            if fields:
                result[f"{method.upper()} {path}"] = fields
    return result


def query_parameters(openapi: dict) -> dict[str, list[str]]:
    """Map route ids to sorted names of string-typed operation query parameters.

    As with writable fields, untyped schemas accept strings and empty routes
    are omitted. Read methods are included. Only parameters declared on each
    operation are inspected; path-item parameters are not inherited.
    """
    result: dict[str, list[str]] = {}
    for path, operations in (openapi.get("paths") or {}).items():
        for method, operation in operations.items():
            if method.lower() not in {
                "get", "put", "post", "delete", "options", "head", "patch", "trace",
            } or not isinstance(operation, dict):
                continue
            names: set[str] = set()
            for parameter in operation.get("parameters") or []:
                parameter = _resolve(parameter, openapi)
                if parameter.get("in") != "query":
                    continue
                name = parameter["name"]
                # Only a leaf at the parameter itself qualifies. Descendants
                # such as q[] or q.value describe arrays/objects, not strings.
                if name in _walk(parameter.get("schema", {}), openapi, name, frozenset()):
                    names.add(name)
            if names:
                result[f"{method.upper()} {path}"] = sorted(names)
    return result
