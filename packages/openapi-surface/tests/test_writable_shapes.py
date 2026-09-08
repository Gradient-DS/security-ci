import pytest

from openapi_surface import writable_string_fields


def body_operation(schema):
    return {"requestBody": {"content": {"application/json": {"schema": schema}}}}


@pytest.mark.parametrize("combinator", ["allOf", "anyOf", "oneOf"])
def test_combinator_wrapped_array_items_and_sibling_refs(combinator):
    doc = {
        "paths": {"/items": {"post": body_operation({"properties": {
            "items": {"type": "array", "items": {combinator: [
                {"$ref": "#/components/schemas/Item"},
            ]}},
            "first": {"$ref": "#/components/schemas/Item"},
            "second": {"$ref": "#/components/schemas/Item"},
        }})}},
        "components": {"schemas": {"Item": {"properties": {
            "label": {"type": "string"},
        }}}},
    }
    assert writable_string_fields(doc) == {
        "POST /items": ["first.label", "items[].label", "second.label"],
    }


def test_untyped_schema_is_stringy_but_free_form_objects_are_not():
    doc = {"paths": {"/items": {"post": body_operation({"properties": {
        "anything": {},
        "metadata": {"type": "object", "additionalProperties": {"type": "string"}},
    }})}}}
    assert writable_string_fields(doc) == {"POST /items": ["anything"]}


@pytest.mark.parametrize("method", ["get", "head", "options"])
def test_all_read_methods_are_excluded(method):
    doc = {"paths": {"/items": {method: body_operation({"properties": {
        "label": {"type": "string"},
    }})}}}
    assert writable_string_fields(doc) == {}
