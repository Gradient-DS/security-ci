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


def _walk(schema: dict, doc: dict, prefix: str, seen: frozenset[int]) -> list[tuple[str, dict]]:
    """Collect every string field reachable from `schema`, as (path, leaf).

    The leaf schema travels with the path because more than one derivation
    needs it: `writable_string_fields` wants only the name, while
    `constrained_string_fields` has to look at the leaf itself to decide
    whether a hostile value could ever survive validation there. Returning
    the pair keeps that judgement in the callers and this traversal --
    the part that is subtle, and the part the docstring below is about --
    the only copy of itself.

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
    out: list[tuple[str, dict]] = []
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
        out.append((prefix, schema))

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
            fields = sorted({path for path, _ in _walk(content.get("schema", {}), openapi, "", frozenset())})
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
                if any(path == name for path, _ in _walk(parameter.get("schema", {}), openapi, name, frozenset())):
                    names.add(name)
            if names:
                result[f"{method.upper()} {path}"] = sorted(names)
    return result


#: Values that the format they stand for will actually parse. A format absent
#: here gets a plain string instead of a guess: a value invented for a format
#: nobody modelled fails validation exactly like no value at all, but reads to
#: whoever finds it as an application finding rather than a gap in this table.
_FORMAT_VALUES = {
    "date": "2026-01-01",
    "date-time": "2026-01-01T00:00:00Z",
    "time": "00:00:00",
    "duration": "PT0S",
    "email": "skeleton@example.invalid",
    "idn-email": "skeleton@example.invalid",
    "hostname": "example.invalid",
    "ipv4": "192.0.2.1",
    "ipv6": "2001:db8::1",
    "uri": "https://example.invalid/",
    "uri-reference": "https://example.invalid/",
    "iri": "https://example.invalid/",
    "url": "https://example.invalid/",
    "uuid": "00000000-0000-4000-8000-000000000000",
}

_SCALARS: dict[str, Any] = {"integer": 0, "number": 0, "boolean": False, "null": None}


def _skeleton(schema: dict, doc: dict, prefix: str, wanted: frozenset[str], seen: frozenset[int]) -> Any:
    """The smallest value this schema accepts, given what the caller will plant.

    Minimal is measured against the planting, not against `required` alone.
    A property is built when the schema demands it, and also when a writable
    string field lives somewhere beneath it: `functions` may be optional, but
    the moment a caller plants `functions[].content` the item it conjures must
    already carry every sibling the item schema requires, or validation
    rejects a body over a field nobody chose to leave out. `wanted` carries
    those container paths, spelled as `_walk` spells them.

    Everything else stays out. A key the schema did not demand and the caller
    will not plant into is a value the caller never asked to send.
    """
    schema = _resolve(schema, doc)
    ident = id(schema)
    if ident in seen:
        # No finite body satisfies an infinitely required chain, and a spec is
        # free to declare one. An empty object is the honest stopping point --
        # the request will 422, but on a bound the spec created, not a hang.
        return {}
    seen = seen | {ident}

    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        # A member, not the empty string: an enum rejects everything else
        # before the handler, so any other choice makes the route unenterable.
        return schema["enum"][0]

    if "allOf" in schema:
        # allOf is a conjunction: every branch's requirements apply at once, so
        # they are merged rather than chosen between.
        merged: dict = {}
        for sub in schema["allOf"]:
            value = _skeleton(sub, doc, prefix, wanted, seen)
            if isinstance(value, dict):
                merged.update(value)
        merged.update(_planted_properties(schema, doc, prefix, wanted, seen))
        return merged

    for combinator in ("anyOf", "oneOf"):
        if schema.get(combinator):
            # `Optional[X]` renders as anyOf[X, null]. `null` would satisfy the
            # schema without exercising anything, so the real branch wins.
            branches = [sub for sub in schema[combinator] if _resolve(sub, doc).get("type") != "null"]
            return _skeleton((branches or schema[combinator])[0], doc, prefix, wanted, seen)

    if schema.get("type") == "array":
        item = _skeleton(schema.get("items", {}), doc, f"{prefix}[]", wanted, seen)
        # One item when the item schema demands fields, because a caller plants
        # into index 0 and an empty list would leave it to invent an item with
        # none of the required siblings -- the 422 this derivation exists to
        # prevent. Zero otherwise, because an item nothing demands is a write
        # the caller did not ask for.
        return [item] if isinstance(item, dict) and item else []

    if "properties" in schema or schema.get("type") == "object":
        return _planted_properties(schema, doc, prefix, wanted, seen)

    if schema.get("type") in _STRINGY:
        return _FORMAT_VALUES.get(schema.get("format"), "")
    return _SCALARS.get(schema.get("type"), "")


def _planted_properties(
    schema: dict, doc: dict, prefix: str, wanted: frozenset[str], seen: frozenset[int]
) -> dict:
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    built = {}
    for name, sub in properties.items():
        path = f"{prefix}.{name}" if prefix else name
        # `path` names the property; `path[]` names its items, which is how a
        # writable field below an array is spelled.
        if name in required or path in wanted or f"{path}[]" in wanted:
            value = _skeleton(sub, doc, path, wanted, seen)
            # An optional container that turned out to hold nothing the schema
            # demands needs no skeleton: the caller's own plant will build it.
            if name in required or value not in ({}, []):
                built[name] = value
    return built


def _containers_of(fields: list[str]) -> frozenset[str]:
    """Every proper prefix of every writable path -- the containers a plant crosses."""
    return frozenset(
        ".".join(segments[:depth])
        for field in fields
        for segments in [field.split(".")]
        for depth in range(1, len(segments))
    )


def body_skeletons(openapi: dict) -> dict[str, Any]:
    """Map route ids to the minimal JSON body their schema accepts.

    A body built only from `writable_string_fields` omits every required bool,
    int, dict and nested scalar the schema also demands, so validation rejects
    it before the handler runs and the route is driven without ever being
    entered. Planting those payloads onto this skeleton instead keeps the body
    valid while every writable field still carries its attack.

    Routes whose body requires nothing map to ``{}`` -- which is the point for
    a caller that would otherwise send no body at all -- while routes with no
    JSON body are absent, because "send an empty body" and "send no body" are
    different requests.
    """
    result: dict[str, Any] = {}
    for path, operations in (openapi.get("paths") or {}).items():
        for method, operation in operations.items():
            if method.lower() in _READ_METHODS or not isinstance(operation, dict):
                continue
            content = ((operation.get("requestBody") or {}).get("content") or {}).get("application/json")
            if content is None:
                continue
            schema = content.get("schema", {})
            wanted = _containers_of([field for field, _ in _walk(schema, openapi, "", frozenset())])
            result[f"{method.upper()} {path}"] = _skeleton(schema, openapi, "", wanted, frozenset())
    return result


def _is_constrained(leaf: dict) -> bool:
    return bool(
        leaf.get("enum")
        or "const" in leaf
        or leaf.get("pattern")
        or leaf.get("format") in _FORMAT_VALUES
    )


def constrained_string_fields(openapi: dict) -> dict[str, list[str]]:
    """Map route ids to the writable string paths a hostile value can never pass.

    An enum, a `const`, a `pattern` or a modelled `format` is checked before
    the handler runs, so a payload written there is rejected whatever it says.
    A caller that leaves these at their skeleton value in the all-fields body
    enters the route, and can still drive each of them individually -- where
    the rejection is the measurement, rather than a route reported as attacked
    and never reached.

    Paths are spelled exactly as `writable_string_fields` spells them, and are
    always a subset of it: the point is to filter one by the other.
    """
    result: dict[str, list[str]] = {}
    for path, operations in (openapi.get("paths") or {}).items():
        for method, operation in operations.items():
            if method.lower() in _READ_METHODS or not isinstance(operation, dict):
                continue
            content = (
                (operation.get("requestBody") or {}).get("content") or {}
            ).get("application/json") or {}
            fields = sorted({
                field
                for field, leaf in _walk(content.get("schema", {}), openapi, "", frozenset())
                if _is_constrained(leaf)
            })
            if fields:
                result[f"{method.upper()} {path}"] = fields
    return result
