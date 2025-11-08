import chromadb
import os
import json

def query_chroma(query_input: str):
    """
    Query ChromaDB collection with flexible input parsing.
    
    Expected formats:
    - "all_logs" -> returns all logs (up to 100)
    - "all_logs 1000010" -> returns logs filtered by signature_id
    - "suricata_rules 1000010" -> returns rule for specific signature
    - "batched_alerts" -> returns all batch summaries
    
    Args:
        query_input: String containing collection name and optional signature_id
    
    Returns:
        JSON string with results or error
    """
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
    
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    except Exception as e:
        return json.dumps({"error": f"Failed to connect to ChromaDB: {str(e)}"})
    
    # Parse input
    parts = query_input.strip().split()
    collection_name = parts[0]
    signature_id = parts[1] if len(parts) > 1 else None
    
    # Validate collection name
    valid_collections = ["all_logs", "suricata_rules", "batched_alerts", "mitre_attack"]
    if collection_name not in valid_collections:
        return json.dumps({
            "error": f"Invalid collection '{collection_name}'. Valid options: {', '.join(valid_collections)}"
        })
    
    try:
        col = client.get_collection(collection_name)
        
        # Build where filter if signature_id provided
        where_filter = None
        if signature_id:
            # Try to convert to int for proper filtering
            try:
                sig_id_int = int(signature_id)
                where_filter = {"signature_id": sig_id_int}
            except ValueError:
                # If conversion fails, try as string
                where_filter = {"signature_id": signature_id}
        
        # Query with appropriate limit
        limit = 100 if not signature_id else 1000  # More results if filtered
        
        data = col.get(
            where=where_filter if where_filter else None,
            include=["documents", "metadatas"],
            limit=limit
        )
        
        # Check if any results
        if not data['ids'] or len(data['ids']) == 0:
            return json.dumps({
                "collection": collection_name,
                "filter": where_filter,
                "count": 0,
                "message": "No results found",
                "results": []
            })
        
        # Format results
        results = []
        for i in range(len(data['documents'])):
            results.append({
                'id': data['ids'][i] if data['ids'] else None,
                'metadata': data['metadatas'][i] if data['metadatas'] else {},
                'document': data['documents'][i] if data['documents'] else ''
            })
        
        # Return summary + limited results for context efficiency
        response = {
            "collection": collection_name,
            "filter": where_filter,
            "total_count": len(results),
            "showing": min(len(results), 20),  # Show first 20 for context
            "results": results[:20]  # Limit for LLM context
        }
        
        # Add helpful summary based on collection type
        if collection_name == "all_logs":
            response["summary"] = f"Found {len(results)} alert logs"
            if signature_id:
                response["summary"] += f" for signature_id {signature_id}"
        elif collection_name == "suricata_rules":
            response["summary"] = f"Found {len(results)} Suricata rules"
        elif collection_name == "batched_alerts":
            response["summary"] = f"Found {len(results)} alert batches"
        
        return json.dumps(response, indent=2)
        
    except ValueError as e:
        # Collection doesn't exist
        return json.dumps({
            "error": f"Collection '{collection_name}' does not exist",
            "available_collections": valid_collections,
            "hint": "Make sure the collection has been created and populated"
        })
    except Exception as e:
        return json.dumps({
            "error": f"Query failed: {str(e)}",
            "collection": collection_name,
            "filter": where_filter if 'where_filter' in locals() else None
        })


def query_chroma_advanced(collection_name: str, where: dict = None, limit: int = None):
    """
    Direct query function for programmatic use (not for LLM agent).
    
    Args:
        collection_name: Name of ChromaDB collection
        where: Dictionary filter (e.g., {"signature_id": 1000010})
        limit: Maximum number of results
    
    Returns:
        JSON string with results
    """
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
    
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        col = client.get_collection(collection_name)
        
        data = col.get(
            where=where if where else None,
            include=["documents", "metadatas"],
            limit=limit or 1000
        )
        
        results = []
        for i in range(len(data['documents'])):
            results.append({
                'id': data['ids'][i] if data['ids'] else None,
                'metadata': data['metadatas'][i] if data['metadatas'] else {},
                'document': data['documents'][i] if data['documents'] else ''
            })
        
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python chroma.py <collection_name> [signature_id]")
        print("Example: python chroma.py all_logs 1000010")
        sys.exit(1)
    
    query = " ".join(sys.argv[1:])
    result = query_chroma(query)
    print(result)