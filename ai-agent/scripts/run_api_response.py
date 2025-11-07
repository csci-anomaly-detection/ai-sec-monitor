import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from validation_layer.feature_analyzer import FeatureAnalyzer
from validation_layer.llm_validator import LLMValidator

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def main():
    """Process api_response.json and analyze threats."""
    
    # Path to api_response.json (from ai-agent folder, go up one level)
    json_path = Path(__file__).parent.parent.parent / "api_response.json"
    
    # Try alternative path if not found
    if not json_path.exists():
        json_path = Path("api_response.json")
        if not json_path.exists():
            print(f"✗ ERROR: Could not find api_response.json")
            print(f"   Tried: {Path(__file__).parent.parent / 'api_response.json'}")
            print(f"   Tried: {Path('api_response.json').absolute()}")
            return
    
    # print("=" * 80)
    # print("Processing api_response.json with FeatureAnalyzer")
    # print("=" * 80)
    # print(f"\nReading from: {json_path.absolute()}\n")
    
    # Initialize analyzer
    analyzer = FeatureAnalyzer(enable_logging=False)  # Disable logging for cleaner output
    
    # Extract threats
    try:
        threats = analyzer._extract_threat_from_api_response(str(json_path))
        # print(f"\n✓ Successfully extracted {len(threats)} threat(s)\n")
    except Exception as e:
        print(f"✗ ERROR: Failed to extract threats: {e}")
        import traceback
        traceback.print_exc()
        return
    if not threats:
        print("⚠ No threats found in api_response.json")
        return
    
    # Analyze each threat
    results = []
    for i, threat in enumerate(threats, 1):
        # print("-" * 80)
        # print(f"ANALYZING THREAT #{i}: {threat.get('ip', 'unknown')}")
        # print("-" * 80)
        try:
            analysis = analyzer.analyze_threat(threat)
            results.append({
                "threat": threat,
                "analysis": analysis
            })
            
            # Display summary (commented out for cleaner output)
            # print(f"\nIP: {threat.get('ip')}")
            # print(f"Severity: {threat.get('severity')}")
            # print(f"Attack Type: {threat.get('attack_type')}")
            # print(f"Total Events: {threat.get('total_events')}")
            # print(f"Confidence Score (ML): {threat.get('confidence_score', 0):.2f}")
            # print(f"\nClassification: {analysis['classification']}")
            # print(f"Feature Analyzer Confidence: {analysis['feature_analyzer_confidence_score']:.2f}")
            # print(f"Reasoning: {analysis['reasoning']}")
            # print(f"\nHeuristic Flags: {', '.join(analysis['heuristic_flags']) if analysis['heuristic_flags'] else 'None'}")
            
            # Show detailed analysis (commented out for cleaner output)
            # timing = analysis['analysis_results']['timing']
            # ip_reputation = analysis['analysis_results']['ip_reputation']
            # traffic = analysis['analysis_results']['traffic']
            
            # print(f"\n--- Timing Analysis ---")
            # print(f"  Business Hours Ratio: {timing['business_hours_ratio']:.2%}")
            # print(f"  Is Business Hours: {timing['is_business_hours']}")
            # print(f"  Is Weekend: {timing['is_weekend']}")
            # print(f"  Timestamp Count: {timing['timestamp_count']}")
            
            # print(f"\n--- IP Reputation Analysis ---")
            # print(f"  Source IPs: {ip_reputation['src_ip_count']}")
            # print(f"  Destination IPs: {ip_reputation['dest_ip_count']}")
            # print(f"  External to Internal: {ip_reputation['external_to_internal']}")
            # print(f"  Internal to Internal: {ip_reputation['internal_to_internal']}")
            
            # print(f"\n--- Traffic Pattern Analysis ---")
            # print(f"  High Volume: {traffic['high_volume']}")
            # print(f"  Events per Minute: {traffic['events_per_minute']:.2f}")
            # print(f"  Rule Violations: {traffic['rule_violation_count']}")
            # print(f"  Has High Severity Rules: {traffic['has_high_severity_rules']}")
            # print(f"  Burst Activity: {traffic['burst_activity']}")
            
        except Exception as e:
            print(f"✗ ERROR analyzing threat: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    # Summary (commented out for cleaner output)
    # print("\n" + "=" * 80)
    # print("SUMMARY")
    # print("=" * 80)
    
    classifications = {}
    for result in results:
        classification = result['analysis']['classification']
        classifications[classification] = classifications.get(classification, 0) + 1
    
    # print(f"\nTotal Threats Analyzed: {len(results)}")
    # for classification, count in classifications.items():
    #     print(f"  {classification}: {count}")
    
    # print("\n✓ Feature Analyzer is complete!")

    # LLM Validation
    # print("\n" + "=" * 80)
    # print("LLM VALIDATION")
    # print("=" * 80)
    
    # Initialize LLM Validator
    # print("\nInitializing LLM Validator...")
    try:
        validator = LLMValidator(
            model="llama3.1:8b",
            enable_logging=False,  # Disable logging for cleaner output
            timeout_seconds=10.0  # Increase timeout for testing
        )
        # print("✓ LLM Validator initialized")
    except Exception as e:
        print(f"✗ ERROR: Failed to initialize LLM Validator: {e}")
        print("   Make sure Ollama is running: ollama serve")
        print("   And model is available: ollama pull llama3.1:8b")
        return
    
    # Validate threats that need LLM review
    llm_results = []
    for i, res in enumerate(results, 1):
        threat = res['threat']
        analysis = res['analysis']
        fa_classification = analysis['classification']
        
        # Only validate threats that need LLM review
        # print(f"\n{'=' * 80}")
        # print(f"LLM VALIDATING THREAT #{i}: {threat.get('ip', 'unknown')}")
        # print(f"{'=' * 80}")
        # print(f"FeatureAnalyzer Classification: {fa_classification}")
        try:
            llm_result = validator.validate(threat, analysis)
            llm_results.append({
                "threat_ip": threat.get('ip'),
                "llm_result": llm_result
            })
            
            # Display LLM validation results (commented out for cleaner output)
            # print(f"\n✓ LLM Validation Complete:")
            # print(f"  Decision: {llm_result['decision']}")
            # print(f"  Confidence: {llm_result['confidence']:.2f}")
            # print(f"  Proceed to Analysis: {llm_result['proceed_to_analysis']}")
            # print(f"  Validator Used: {llm_result['validator_used']}")
            # print(f"  Latency: {llm_result['latency_ms']:.2f}ms")
            # print(f"\n  Reasoning: {llm_result['reasoning']}")
            
            # if llm_result.get('errors'):
            #     print(f"\n  ⚠ Errors/Warnings: {', '.join(llm_result['errors'])}")
            
        except Exception as e:
            print(f"✗ ERROR during LLM validation: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    # Merge LLM results back into the original results
    print(f"\nMerging LLM validation results...")
    for result in results:
        threat_ip = result['threat'].get('ip')
        # Find matching LLM result
        matching_llm = next(
            (lr for lr in llm_results if lr['threat_ip'] == threat_ip),
            None
        )
        if matching_llm:
            result['llm_validation'] = matching_llm['llm_result']
        else:
            result['llm_validation'] = None
    
    # Save combined results to JSON file
    output_path = Path(__file__).parent.parent / "validation_results.json"
    print(f"Saving results to: {output_path}")

    # Prepare summary data
    llm_decisions = {}
    if llm_results:
        for res in llm_results:
            decision = res['llm_result']['decision']
            llm_decisions[decision] = llm_decisions.get(decision, 0) + 1

    avg_latency = 0
    if llm_results:
        avg_latency = sum(r['llm_result']['latency_ms'] for r in llm_results) / len(llm_results)
    
    output_data = {
        "summary": {
            "total_threats": len(results),
            "feature_analyzer_classifications": classifications,
            "llm_validations_performed": len(llm_results),
            "llm_decisions": llm_decisions,
            "average_llm_latency_ms": round(avg_latency, 2)
        },
        "detailed_results": results
    }

    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2, cls=DateTimeEncoder)
    
    print(f"✓ Results saved successfully!")
    print(f"\nSummary:")
    print(f"  Total Threats: {len(results)}")
    print(f"  LLM Validations: {len(llm_results)}")
    print(f"  Average LLM Latency: {avg_latency:.2f}ms")
    print(f"\nLLM Decisions:")
    for decision, count in llm_decisions.items():
        print(f"  {decision}: {count}")

    # Final Summary (commented out for cleaner output)
    # print("\n" + "=" * 80)
    # print("FINAL SUMMARY")
    # print("=" * 80)
    
    # print(f"\nTotal Threats Processed: {len(results)}")
    # print(f"FeatureAnalyzer Classifications:")
    # for classification, count in classifications.items():
    #     print(f"  {classification}: {count}")
    
    # if llm_results:
    #     print(f"\nLLM Validations: {len(llm_results)}")
    #     llm_decisions = {}
    #     for res in llm_results:
    #         decision = res['llm_result']['decision']
    #         llm_decisions[decision] = llm_decisions.get(decision, 0) + 1
    #     
    #     print(f"LLM Final Decisions:")
    #     for decision, count in llm_decisions.items():
    #         print(f"  {decision}: {count}")
    #     
    #     # Calculate average latency
    #     avg_latency = sum(r['llm_result']['latency_ms'] for r in llm_results) / len(llm_results)
    #     print(f"\nAverage LLM Latency: {avg_latency:.2f}ms")
    #     
    #     # Count fallback usage
    #     fallback_count = sum(1 for r in llm_results if r['llm_result']['validator_used'] == 'fallback')
    #     if fallback_count > 0:
    #         print(f"⚠ Fallback Validations: {fallback_count} (LLM was unavailable)")
    
    # print("\n✓ Testing complete!")


if __name__ == "__main__":
    main()

