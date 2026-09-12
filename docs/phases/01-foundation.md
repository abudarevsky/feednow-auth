# Current state: foundation

The repository currently contains the Phase 01 foundation:

- runtime package under `src/app` and tests under `src/tests`;
- provider-neutral domain entities and value types;
- versioned API schemas and a ten-route endpoint manifest;
- health-only FastAPI app factory with no database or AWS initialization;
- production Uvicorn standard extras, including `uvloop` where supported.

The application currently exposes `/health`. Storage, provider validation,
resource CRUD, and deployment behavior are not implemented in the current
application state.
