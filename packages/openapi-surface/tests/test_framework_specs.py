"""Request-only slices of the Phase 0 SpecTree and FastAPI reference specs."""

import json
from pathlib import Path

from openapi_surface import query_parameters, writable_string_fields


FIXTURES = Path(__file__).parent / "fixtures"


def test_spectree_request_surface():
    doc = json.loads((FIXTURES / "aire-openapi.json").read_text())
    assert writable_string_fields(doc) == {
        "POST /conversations": [
            "date", "description", "document_ids", "main_question", "title", "type",
        ],
        "POST /save-search-results": [
            "results[].source_type", "results[].title", "results[].url",
        ],
        "POST /filesystem/bulk/copy": ["nodeIds", "targetParentId"],
    }
    assert query_parameters(doc) == {}


def test_fastapi_request_surface():
    doc = json.loads((FIXTURES / "owui-openapi.json").read_text())
    assert writable_string_fields(doc) == {
        "POST /api/v1/models/create": [
            "base_model_id", "id", "meta.description", "meta.profile_image_url", "name",
        ],
        "POST /api/v1/knowledge/{id}/files/batch/add": [
            "[].directory_id", "[].file_id",
        ],
        "POST /api/v1/chats/{id}/compact": ["model"],
    }
    assert query_parameters(doc) == {"GET /api/v1/chats/search": ["text"]}
