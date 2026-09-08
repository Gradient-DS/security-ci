"""Attacker-writable fields are derived from the spec, never listed by hand.

A list of writable fields rots the moment someone adds one.  A derivation
cannot.  These tests pin the shapes SpecTree actually emits -- $ref indirection,
nesting, arrays, and the combinators -- because every one of them is a place a
field could hide from the attack plane.
"""

import json
from pathlib import Path

from openapi_surface import writable_string_fields

SPEC = Path(__file__).parent / "fixtures" / "aire-openapi.json"


def test_a_flat_string_field_is_writable():
    doc = {
        "paths": {
            "/api/message": {
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"properties": {"content": {"type": "string"}}}}}}}
            }
        }
    }
    assert writable_string_fields(doc) == {"POST /api/message": ["content"]}


def test_refs_are_resolved_and_nesting_is_not_a_hiding_place():
    doc = {
        "paths": {
            "/api/message": {
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Message"}}}}},
                "get": {},
            }
        },
        "components": {"schemas": {"Message": {"properties": {
            "content": {"type": "string"},
            "meta": {"properties": {"title": {"type": "string"}}},
            "count": {"type": "integer"},
        }}}},
    }
    assert writable_string_fields(doc) == {
        "POST /api/message": ["content", "meta.title"]
    }


def test_arrays_of_strings_are_writable():
    doc = {
        "paths": {"/api/bulk": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "ids": {"type": "array", "items": {"type": "string"}}}}}}}}}}
    }
    assert writable_string_fields(doc) == {"POST /api/bulk": ["ids[]"]}


def test_combinators_are_walked():
    doc = {
        "paths": {"/api/x": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"anyOf": [
                {"properties": {"a": {"type": "string"}}},
                {"properties": {"b": {"type": "string"}}},
            ]}}}}}}}
    }
    assert writable_string_fields(doc) == {"POST /api/x": ["a", "b"]}


def test_ref_cycles_terminate():
    """SpecTree emits self-referential schemas for tree-shaped models; a naive
    walk recurses forever and the suite hangs rather than fails."""
    doc = {
        "paths": {"/api/tree": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}},
        "components": {"schemas": {"Node": {"properties": {
            "name": {"type": "string"},
            "child": {"$ref": "#/components/schemas/Node"},
        }}}},
    }
    assert writable_string_fields(doc)["POST /api/tree"] == ["name"]


def test_optional_nested_model_is_not_mistaken_for_a_string_leaf():
    """SpecTree renders ``Optional[Model]`` as ``anyOf: [Model, null]``. The
    property's own top-level dict then carries neither ``type`` nor
    ``properties`` -- both live one level down, inside the ``anyOf`` branches
    -- so a leaf check that fires before combinators are considered mistakes
    the whole property for an untyped string and never looks inside it."""
    doc = {
        "paths": {"/api/profile": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "name": {"type": "string"},
                "address": {"anyOf": [
                    {"type": "object", "properties": {
                        "street": {"type": "string"},
                        "city": {"type": "string"},
                    }},
                    {"type": "null"},
                ]},
            }}}}}}}}
    }
    assert writable_string_fields(doc) == {
        "POST /api/profile": ["address.city", "address.street", "name"]
    }


def test_optional_array_of_models_is_not_mistaken_for_a_string_leaf():
    """Same trap one level deeper: ``Optional[list[Model]]`` renders as
    ``anyOf: [array-of-Model, null]``, so the array-items branch needs the
    same combinator-aware leaf check as the properties branch does."""
    doc = {
        "paths": {"/api/profile": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "addresses": {"anyOf": [
                    {"type": "array", "items": {"type": "object", "properties": {
                        "street": {"type": "string"},
                    }}},
                    {"type": "null"},
                ]},
            }}}}}}}}
    }
    assert writable_string_fields(doc) == {
        "POST /api/profile": ["addresses[].street"]
    }


def test_read_methods_are_skipped():
    doc = {
        "paths": {"/api/x": {"get": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {"a": {"type": "string"}}}}}}}}}
    }
    assert writable_string_fields(doc) == {}


def test_the_real_spec_yields_fields_for_the_routes_that_take_bodies():
    """A derivation that silently returns nothing is worse than no derivation:
    the attack plane would plant into no field and still report success."""
    derived = writable_string_fields(json.loads(SPEC.read_text()))
    # The trimmed SpecTree fixture retains three writable operations and the
    # boolean-only favorite operation from the original full-spec smoke test.
    assert len(derived) == 3
    assert "PATCH /user-documents/{document_id}/favorite" not in derived
    assert derived["POST /conversations"], "POST /conversations takes a title"
