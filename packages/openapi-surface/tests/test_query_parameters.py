import pytest

from openapi_surface import query_parameters


def query_doc(schema):
    return {"paths": {"/search": {"get": {"parameters": [
        {"name": "q", "in": "query", "schema": schema},
    ]}}}}


def test_string_query_parameter_is_found():
    assert query_parameters(query_doc({"type": "string"})) == {"GET /search": ["q"]}


@pytest.mark.parametrize("schema", [
    {"type": "integer"},
    {"type": "boolean"},
    {"type": "null"},
    {"type": "array", "items": {"type": "string"}},
    {"type": "object", "properties": {"value": {"type": "string"}}},
    {"anyOf": [{"type": "integer"}, {"type": "null"}]},
])
def test_non_string_query_parameters_are_excluded(schema):
    assert query_parameters(query_doc(schema)) == {}


def test_ref_enum_resolves():
    doc = query_doc({"$ref": "#/components/schemas/SortOrder"})
    doc["components"] = {"schemas": {
        "SortOrder": {"type": "string", "enum": ["asc", "desc"]},
    }}
    assert query_parameters(doc) == {"GET /search": ["q"]}


@pytest.mark.parametrize("combinator", ["allOf", "anyOf", "oneOf"])
def test_combinators_resolve_string_branches(combinator):
    doc = query_doc({combinator: [{"$ref": "#/components/schemas/Term"}]})
    doc["components"] = {"schemas": {"Term": {"type": "string"}}}
    assert query_parameters(doc) == {"GET /search": ["q"]}


def test_untyped_schema_is_stringy():
    assert query_parameters(query_doc({})) == {"GET /search": ["q"]}


def test_ref_cycles_terminate_without_hiding_a_string_branch():
    doc = query_doc({"$ref": "#/components/schemas/Recursive"})
    doc["components"] = {"schemas": {"Recursive": {"anyOf": [
        {"$ref": "#/components/schemas/Recursive"}, {"type": "string"},
    ]}}}
    assert query_parameters(doc) == {"GET /search": ["q"]}


def test_parameter_reference_resolves():
    doc = {"paths": {"/search": {"post": {"parameters": [
        {"$ref": "#/components/parameters/Term"},
    ]}}}, "components": {"parameters": {"Term": {
        "name": "q", "in": "query", "schema": {"type": "string"},
    }}}}
    assert query_parameters(doc) == {"POST /search": ["q"]}


def test_names_are_sorted_unique_and_only_from_query_parameters():
    parameters = [
        {"name": name, "in": location, "schema": {"type": "string"}}
        for name, location in [
            ("z", "query"), ("a", "query"), ("z", "query"),
            ("id", "path"), ("token", "header"), ("session", "cookie"),
        ]
    ]
    doc = {"paths": {"/search": {
        "summary": "Search", "parameters": [],
        "x-metadata": {"parameters": parameters},
        "get": {"parameters": parameters},
    }}}
    assert query_parameters(doc) == {"GET /search": ["a", "z"]}


@pytest.mark.parametrize("doc", [
    {}, {"paths": None},
    {"paths": {"/search": {"get": {}}}},
    {"paths": {"/search": {"get": {"parameters": []}}}},
    {"paths": {"/search": {"get": {"parameters": None}}}},
])
def test_operations_without_parameters_yield_nothing(doc):
    assert query_parameters(doc) == {}
