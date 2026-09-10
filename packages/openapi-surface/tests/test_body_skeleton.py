"""A body the schema accepts, so the hostile string reaches the handler.

`writable_string_fields` reports only string leaves, so a body built from it
alone omits every required bool, int, dict and nested scalar the schema also
demands.  FastAPI then answers 422 before the handler runs, and the attack
plane records a route it drove hundreds of times and never entered once.
These tests pin the skeleton that closes that gap: the minimal body satisfying
`required`, onto which the caller plants its payloads.

The second derivation here is the other half of the same problem.  A hostile
string written into a field the spec constrains -- an enum, a `format`, a
`pattern` -- can never get past validation, whatever it says.  Reporting those
paths lets a caller leave them at their skeleton value in the all-fields body
(so the route is entered) while still driving them individually (so the
constraint's rejection is still measured).
"""

import pytest

from openapi_surface import body_skeletons, constrained_string_fields


def body_operation(schema):
    return {"requestBody": {"content": {"application/json": {"schema": schema}}}}


def doc_for(schema, path="/items", method="post"):
    return {"paths": {path: {method: body_operation(schema)}}}


def skeleton(schema):
    return body_skeletons(doc_for(schema))["POST /items"]


def constrained(schema):
    return constrained_string_fields(doc_for(schema)).get("POST /items", [])


def test_a_route_whose_body_requires_nothing_still_gets_an_empty_body():
    # Not a no-op: the plane's drive pass sends no body at all today, so a
    # route whose fields are all optional answers 422 to the request that was
    # supposed to cover it. `{}` is what enters that handler.
    assert skeleton({"type": "object", "properties": {"name": {"type": "string"}}}) == {}


def test_a_route_with_no_json_body_is_absent_rather_than_empty():
    # Absent and `{}` mean different things to a caller deciding whether to
    # send a body at all, and a GET with a body is not the same request.
    assert body_skeletons({"paths": {"/items": {"post": {}}}}) == {}


@pytest.mark.parametrize("method", ["get", "head", "options"])
def test_read_methods_are_excluded_as_they_are_everywhere_else(method):
    assert body_skeletons(doc_for({"type": "object"}, method=method)) == {}


def test_every_scalar_type_gets_a_value_its_own_type_accepts():
    assert skeleton({
        "type": "object",
        "required": ["name", "count", "ratio", "enabled", "anything"],
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "enabled": {"type": "boolean"},
            "anything": {},
        },
    }) == {"name": "", "count": 0, "ratio": 0, "enabled": False, "anything": ""}


def test_optional_fields_are_left_out_so_the_body_stays_minimal():
    # The skeleton exists to be overwritten. Every key it invents that the
    # schema did not demand is a value the caller did not choose to send.
    assert skeleton({
        "type": "object",
        "required": ["needed"],
        "properties": {"needed": {"type": "string"}, "spare": {"type": "string"}},
    }) == {"needed": ""}


def test_a_required_enum_takes_a_member_rather_than_the_empty_string():
    assert skeleton({
        "type": "object",
        "required": ["category"],
        "properties": {"category": {"type": "string", "enum": ["bug", "idea"]}},
    }) == {"category": "bug"}


def test_a_required_const_takes_the_only_value_it_can_have():
    assert skeleton({
        "type": "object",
        "required": ["kind"],
        "properties": {"kind": {"const": "note"}},
    }) == {"kind": "note"}


@pytest.mark.parametrize(
    "fmt,check",
    [
        ("date", lambda v: v.count("-") == 2 and len(v) == 10),
        ("date-time", lambda v: v.endswith("Z") and "T" in v),
        ("uri", lambda v: v.startswith("https://")),
        ("email", lambda v: "@" in v),
        ("uuid", lambda v: len(v) == 36 and v.count("-") == 4),
    ],
)
def test_a_required_format_takes_a_value_that_format_parses(fmt, check):
    value = skeleton({
        "type": "object",
        "required": ["field"],
        "properties": {"field": {"type": "string", "format": fmt}},
    })["field"]
    assert check(value), f"{fmt} skeleton {value!r} would not parse"


def test_an_unknown_format_falls_back_to_a_plain_string():
    # Guessing a value for a format nobody here knows would fail validation in
    # a way that reads as an application finding rather than a harness gap.
    assert skeleton({
        "type": "object",
        "required": ["field"],
        "properties": {"field": {"type": "string", "format": "iban"}},
    }) == {"field": ""}


def test_nested_objects_are_satisfied_all_the_way_down():
    assert skeleton({
        "type": "object",
        "required": ["context"],
        "properties": {"context": {
            "type": "object",
            "required": ["trace_id", "attempt"],
            "properties": {"trace_id": {"type": "string"}, "attempt": {"type": "integer"}},
        }},
    }) == {"context": {"trace_id": "", "attempt": 0}}


def test_refs_are_resolved_like_everywhere_else():
    doc = {
        "paths": {"/items": {"post": body_operation({"$ref": "#/components/schemas/Report"})}},
        "components": {"schemas": {"Report": {
            "type": "object", "required": ["id"], "properties": {"id": {"type": "string"}},
        }}},
    }
    assert body_skeletons(doc) == {"POST /items": {"id": ""}}


def test_an_array_of_objects_that_demand_fields_gets_exactly_one_item():
    # One, not zero: the caller plants into index 0, so an empty list would
    # leave `_plant` to invent an item with none of the required siblings --
    # which is the 422 this whole derivation exists to prevent. One, not two:
    # a second item is a second write the caller never asked for.
    assert skeleton({
        "type": "object",
        "required": ["chats"],
        "properties": {"chats": {"type": "array", "items": {
            "type": "object", "required": ["chat"], "properties": {"chat": {"type": "string"}},
        }}},
    }) == {"chats": [{"chat": ""}]}


def test_an_array_whose_items_demand_nothing_stays_empty():
    assert skeleton({
        "type": "object",
        "required": ["tags"],
        "properties": {"tags": {"type": "array", "items": {"type": "string"}}},
    }) == {"tags": []}


def test_a_free_form_object_is_an_empty_object_not_a_string():
    # `dict[str, str]` renders as additionalProperties. Planting a bare string
    # where the schema declares an object is the failure `_walk` documents at
    # length; the skeleton must not reintroduce it from the other side.
    assert skeleton({
        "type": "object",
        "required": ["params"],
        "properties": {"params": {"type": "object", "additionalProperties": {"type": "string"}}},
    }) == {"params": {}}


def test_optional_null_unions_pick_the_branch_that_is_not_null():
    # `Optional[X]` renders as anyOf[X, null]. When such a field is required
    # (Pydantic's "required but nullable"), null satisfies it -- but a value
    # of the real type is what exercises the field.
    assert skeleton({
        "type": "object",
        "required": ["source"],
        "properties": {"source": {"anyOf": [
            {"type": "string", "enum": ["tool", "background_review"]},
            {"type": "null"},
        ]}},
    }) == {"source": "tool"}


def test_allof_is_merged_rather_than_picked_from():
    assert skeleton({"allOf": [
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
        {"type": "object", "required": ["b"], "properties": {"b": {"type": "integer"}}},
    ]}) == {"a": "", "b": 0}


def test_a_recursive_schema_terminates():
    doc = {
        "paths": {"/items": {"post": body_operation({"$ref": "#/components/schemas/Node"})}},
        "components": {"schemas": {"Node": {
            "type": "object",
            "required": ["label", "child"],
            "properties": {
                "label": {"type": "string"},
                "child": {"$ref": "#/components/schemas/Node"},
            },
        }}},
    }
    # The cycle is cut with an empty object: there is no finite body that
    # satisfies an infinitely required chain, and hanging is not an option.
    assert body_skeletons(doc) == {"POST /items": {"label": "", "child": {}}}


def test_constrained_paths_are_reported_so_a_caller_can_leave_them_alone():
    assert constrained({
        "type": "object",
        "properties": {
            "category": {"type": "string", "enum": ["bug", "idea"]},
            "url": {"type": "string", "format": "uri"},
            "slug": {"type": "string", "pattern": "^[a-z]+$"},
            "title": {"type": "string"},
        },
    }) == ["category", "slug", "url"]


def test_constrained_paths_are_found_under_arrays_and_nesting_too():
    assert constrained({
        "type": "object",
        "properties": {"items": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["page", "space"]},
                "name": {"type": "string"},
            },
        }}},
    }) == ["items[].type"]


def test_a_constrained_field_is_a_subset_of_the_writable_fields():
    # The two derivations must agree on path spelling, or a caller cannot use
    # one to filter the other -- which is the only reason this one exists.
    from openapi_surface import writable_string_fields

    doc = doc_for({
        "type": "object",
        "properties": {"items": {"type": "array", "items": {
            "type": "object", "properties": {"type": {"type": "string", "enum": ["page"]}},
        }}},
    })
    assert set(constrained_string_fields(doc)["POST /items"]) <= set(
        writable_string_fields(doc)["POST /items"]
    )


def test_an_unconstrained_route_is_absent_rather_than_empty():
    assert constrained_string_fields(doc_for({
        "type": "object", "properties": {"title": {"type": "string"}},
    })) == {}


def test_an_optional_container_holding_a_writable_field_is_built_out():
    # The skeleton is minimal with respect to what the caller will *plant*, not
    # to `required` alone. `functions` is optional, so a purely required-driven
    # skeleton omits it -- and then the caller plants `functions[].content`,
    # conjuring an item that carries none of the siblings the item schema
    # demands. The 422 that follows names a field nobody chose to leave out.
    assert skeleton({
        "type": "object",
        "properties": {"functions": {"type": "array", "items": {
            "type": "object",
            "required": ["id", "created_at"],
            "properties": {
                "id": {"type": "string"},
                "created_at": {"type": "integer"},
                "content": {"type": "string"},
            },
        }}},
    }) == {"functions": [{"id": "", "created_at": 0}]}


def test_an_optional_container_with_no_writable_field_below_it_stays_out():
    # The other half of the same rule: nothing is planted here, so building it
    # would be the skeleton sending a value the caller never asked for.
    assert skeleton({
        "type": "object",
        "properties": {"window": {
            "type": "object",
            "required": ["from_ts"],
            "properties": {"from_ts": {"type": "integer"}},
        }},
    }) == {}


def test_containers_are_built_out_to_the_depth_the_planting_reaches():
    assert skeleton({
        "type": "object",
        "properties": {"models": {"type": "array", "items": {
            "type": "object",
            "required": ["is_active"],
            "properties": {
                "is_active": {"type": "boolean"},
                "meta": {
                    "type": "object",
                    "required": ["revision"],
                    "properties": {
                        "revision": {"type": "integer"},
                        "description": {"type": "string"},
                    },
                },
            },
        }}},
    }) == {"models": [{"is_active": False, "meta": {"revision": 0}}]}
