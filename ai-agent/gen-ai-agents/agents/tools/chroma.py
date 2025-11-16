import chromadb
from chromadb.utils import embedding_functions
import os
import json
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ============================================================================
# UNIFIED EMBEDDING FUNCTION - Use same across all collections
# ============================================================================

# Use DefaultEmbeddingFunction everywhere for consistency
embedding_fn = embedding_functions.DefaultEmbeddingFunction()
logger.info("✅ Using DefaultEmbeddingFunction for all collections")


def get_chroma_client():
    """Get ChromaDB client with error handling"""
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
    
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        return client
    except Exception as e:
        logger.error(f"❌ Failed to connect to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
        raise


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
    
    try:
        client = get_chroma_client()
    except Exception as e:
        return json.dumps({"error": f"Failed to connect to ChromaDB: {str(e)}"})
    
    # Parse input
    parts = query_input.strip().split()
    collection_name = parts[0]
    signature_id = parts[1] if len(parts) > 1 else None
    
    # Validate collection name
    valid_collections = ["all_logs", "suricata_rules", "batched_alerts", "mitre_attack", "all_threats", "analyst_reports"]
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
        
        logger.info(f"✅ Query successful: {collection_name} returned {len(results)} results")
        return json.dumps(response, indent=2)
        
    except ValueError as e:
        # Collection doesn't exist
        logger.warning(f"⚠️ Collection '{collection_name}' does not exist")
        return json.dumps({
            "error": f"Collection '{collection_name}' does not exist",
            "available_collections": valid_collections,
            "hint": "Make sure the collection has been created and populated"
        })
    except Exception as e:
        logger.error(f"❌ Query failed: {str(e)}")
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
    
    try:
        client = get_chroma_client()
    except Exception as e:
        return json.dumps({"error": f"Failed to connect to ChromaDB: {str(e)}"})
    
    try:
        col = client.get_collection(collection_name)
        logger.info(f"✅ Querying collection: {collection_name}")
        
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
        
        logger.info(f"✅ Found {len(results)} results")
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"❌ Advanced query failed: {str(e)}")
        return json.dumps({"error": str(e)})


def query_chroma_semantic(query_text: str, collection_name: str = "all_threats", top_k: int = 2):
    """
    Semantic search in ChromaDB using embeddings (WITHOUT specifying embedding function).
    
    ChromaDB will use the embedding function already stored in the collection.
    This avoids the "embedding function conflict" error.
    
    Args:
        query_text: Natural language query (e.g., "SQL injection attacks from suspicious IPs")
        collection_name: ChromaDB collection to search
        top_k: Number of most similar results to return
    
    Returns:
        JSON string with semantically similar results
    """
    
    try:
        client = get_chroma_client()
    except Exception as e:
        return json.dumps({"error": f"Failed to connect to ChromaDB: {str(e)}"})
    
    try:
        # Get collection WITHOUT specifying embedding_function
        # This forces ChromaDB to use the one already stored in the collection
        col = client.get_collection(
            name=collection_name
            # ⚠️ DO NOT pass embedding_function here - it causes conflicts!
        )
        
        logger.info(f"✅ Querying collection '{collection_name}' semantically")
        logger.info(f"   Query: '{query_text}'")
        
        # Query by semantic similarity
        results = col.query(
            query_texts=[query_text],
            n_results=top_k,
            include=["documents", "metadatas", "distances"]
        )
        
        # Format results
        formatted = []
        if results['ids'] and len(results['ids']) > 0:
            for i in range(len(results['ids'][0])):
                similarity_score = 1 - results['distances'][0][i]  # Convert distance to similarity
                formatted.append({
                    'id': results['ids'][0][i],
                    'document': results['documents'][0][i][:300] if results['documents'][0][i] else '',
                    'metadata': results['metadatas'][0][i],
                    'similarity_score': round(similarity_score, 3)
                })
        
        logger.info(f"✅ Found {len(formatted)} similar results")
        
        response = {
            "query": query_text,
            "collection": collection_name,
            "result_count": len(formatted),
            "results": formatted
        }
        # logger.info(response)
        return json.dumps(response, indent=2)
        
    except Exception as e:
        logger.error(f"❌ Semantic search failed: {str(e)}")
        logger.error(f"   Collection: {collection_name}")
        logger.error(f"   Query: {query_text}")
        
        return json.dumps({
            "error": f"Semantic search failed: {str(e)}",
            "query": query_text,
            "collection": collection_name,
            "hint": "Make sure the collection exists and has documents"
        })


def get_collection_stats(collection_name: str):
    """Get statistics about a collection"""
    try:
        client = get_chroma_client()
        col = client.get_collection(collection_name)
        
        # Get total count
        all_data = col.get(limit=1)
        total = len(all_data['ids']) if all_data['ids'] else 0
        
        logger.info(f"📊 Collection '{collection_name}': {total} documents")
        
        return {
            "collection": collection_name,
            "total_documents": total,
            "status": "OK"
        }
    except Exception as e:
        logger.error(f"❌ Could not get stats for '{collection_name}': {str(e)}")
        return {
            "collection": collection_name,
            "error": str(e),
            "status": "ERROR"
        }


# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python chroma.py <command> [args]")
        print("Commands:")
        print("  query <collection> [signature_id]")
        print("  semantic <collection> '<query>'")
        print("  stats <collection>")
        print("\nExamples:")
        print("  python chroma.py query all_logs 1000010")
        print("  python chroma.py semantic all_threats 'SQL injection'")
        print("  python chroma.py stats all_threats")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "semantic" and len(sys.argv) > 3:
        collection = sys.argv[2]
        query_text = " ".join(sys.argv[3:])
        result = query_chroma_semantic(query_text, collection_name=collection)
        print(result)
    elif command == "query" and len(sys.argv) > 2:
        query = " ".join(sys.argv[2:])
        result = query_chroma(query)
        print(result)
    elif command == "stats" and len(sys.argv) > 2:
        collection = sys.argv[2]
        result = get_collection_stats(collection)
        print(json.dumps(result, indent=2))
    else:
        print("❌ Invalid command or arguments")
        sys.exit(1)