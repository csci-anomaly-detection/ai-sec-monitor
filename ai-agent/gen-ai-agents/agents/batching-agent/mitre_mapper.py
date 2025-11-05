import json
import chromadb
import os

def map_signatures_to_mitre(batching_analysis_result):
    """
    Enrich batching analysis with MITRE ATT&CK mappings.
    Input: batching_analysis_result (list of dicts)
    Output: enriched analysis list with MITRE data
    """
    try:
        # Parse if string
        if isinstance(batching_analysis_result, str):
            analysis = json.loads(batching_analysis_result)
        else:
            analysis = batching_analysis_result
        
        if not isinstance(analysis, list):
            analysis = [analysis]
        
        # Connect to ChromaDB
        CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
        CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        
        # Get collections
        suricata_col = client.get_collection("suricata_rules")
        mitre_col = client.get_collection("mitre_attack")
        
        # Enrich each signature
        enriched_analysis = []
        for item in analysis:
            sig_id = item.get("signature_id")
            
            try:
                # Step 1: Get Suricata rule by signature_id
                suricata_result = suricata_col.get(
                    ids=[str(sig_id)],
                    include=["metadatas"]
                )
                
                if suricata_result['ids'] and len(suricata_result['ids']) > 0:
                    suricata_rule = suricata_result['metadatas'][0]
                    mitre_id = suricata_rule.get("mitre_id", "N/A")
                    
                    # Step 2: Get MITRE technique details by mitre_id
                    if mitre_id and mitre_id != "N/A":
                        mitre_result = mitre_col.get(
                            ids=[mitre_id],
                            include=["metadatas"]
                        )
                        
                        if mitre_result['ids'] and len(mitre_result['ids']) > 0:
                            mitre_technique = mitre_result['metadatas'][0]
                            technique_name = mitre_technique.get("name", "Unknown")
                            technique_description = mitre_technique.get("description", "No description available")
                        else:
                            technique_name = "Unknown"
                            technique_description = f"MITRE technique {mitre_id} not found in database"
                    else:
                        technique_name = "Unknown"
                        technique_description = "No MITRE mapping available"
                else:
                    # Suricata rule not found
                    mitre_id = "N/A"
                    technique_name = "Unknown"
                    technique_description = f"Signature {sig_id} not found in Suricata rules"
                
            except Exception as e:
                print(f"⚠️  Error looking up signature {sig_id}: {e}")
                mitre_id = "N/A"
                technique_name = "Unknown"
                technique_description = "Lookup error"
            
            # Build enriched item
            enriched_item = {
                **item,
                "mitre": {
                    "technique_id": mitre_id,
                    "technique_name": technique_name,
                    "technique_description": technique_description
                }
            }
            enriched_analysis.append(enriched_item)
        
        return enriched_analysis
    
    except Exception as e:
        print(f"❌ Error mapping signatures to MITRE: {e}")
        return batching_analysis_result  # Return original if enrichment fails

def format_mitre_enriched_report(enriched_analysis):
    """Format enriched analysis for readability."""
    report = []
    
    for item in enriched_analysis:
        report.append({
            "signature_id": item.get("signature_id"),
            "severity": item.get("severity"),
            "reasoning": item.get("reasoning", []),
            "mitre_mapping": {
                "technique_id": item.get("mitre", {}).get("technique_id"),
                "technique_name": item.get("mitre", {}).get("technique_name"),
                "technique_description": item.get("mitre", {}).get("technique_description")
            }
        })
    
    return report