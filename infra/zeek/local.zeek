@load policy/tuning/json-logs.zeek

# Keep files small for shippers (Loki/OpenSearch)
redef Log::default_rotation_interval = 1hr;

# NOTE:
# Core analyzers (conn, dns, http, ssl) are loaded by default in Zeek official images.
# No need to @load protocols/conn etc., which vary by version/path and caused your error.
