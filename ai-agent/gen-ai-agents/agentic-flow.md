    ```mermaid
    flowchart TD
        Start([Pipeline Start]) --> CheckDirs{Directories<br/>Exist?}
        CheckDirs -->|No| CreateDirs[Create logs/<br/>output/ dirs]
        CheckDirs -->|Yes| Stage1
        CreateDirs --> Stage1
        
        %% ===== STAGE 1: PREPROCESSING & BATCHING =====
        Stage1[/"🔷 STAGE 1: PREPROCESSING & BATCHING"/]
        
        Stage1 --> ReadLogs[Read eve.json<br/>Suricata logs]
        ReadLogs --> ParseJSON{Valid JSON?}
        ParseJSON -->|No| Error1[Error: Invalid logs]
        ParseJSON -->|Yes| PreProcess[preprocessor.py<br/>Clean & normalize alerts]
        
        PreProcess --> BatchAlerts[pre_batch.py<br/>Group by signature_id]
        BatchAlerts --> StoreDB[(Store batches in<br/>PostgreSQL)]
        StoreDB --> BatchedData[Batched Data List]
        
        BatchedData --> CheckBatches{Has batched<br/>data?}
        CheckBatches -->|No| Error2[Error: No batched data]
        CheckBatches -->|Yes| Stage2
        
        %% ===== STAGE 2: BATCHING AGENT ANALYSIS =====
        Stage2[/"🔷 STAGE 2: BATCHING AGENT ANALYSIS"/]
        
        Stage2 --> InitReact[Initialize ReAct Agent<br/>LLM: Ollama llama3.1:8b]
        InitReact --> ReactLoop{ReAct Iteration<br/>< max?}
        
        ReactLoop -->|Yes| Think[Agent Thought:<br/>Analyze signatures]
        Think --> ChooseTool{Choose Tool}
        
        ChooseTool -->|PostgresQuery| PG[Query alert_batches<br/>historical patterns]
        ChooseTool -->|ChromaQuery| CH[Query all_logs<br/>signature details]
        ChooseTool -->|RelevanceScore| REL[Check tech stack<br/>relevance]
        
        PG --> Observe[Observation:<br/>Tool Result]
        CH --> Observe
        REL --> Observe
        
        Observe --> ReactLoop
        
        ReactLoop -->|Max iterations<br/>or Final Answer| ReactResult[ReAct Analysis Result<br/>JSON list with severity]
        
        ReactResult --> Stage3
        
        %% ===== STAGE 3: MITRE ENRICHMENT =====
        Stage3[/"🔷 STAGE 3: MITRE ENRICHMENT"/]
        
        Stage3 --> ConnectChroma[Connect to ChromaDB<br/>chroma:8000]
        ConnectChroma --> GetCollections[Get collections:<br/>suricata_rules<br/>mitre_attack]
        
        GetCollections --> LoopSigs{For each<br/>signature_id}
        
        LoopSigs -->|Next| QuerySuricata[Query suricata_rules<br/>by signature_id]
        QuerySuricata --> GetMitreID[Extract mitre_id<br/>from metadata]
        GetMitreID --> QueryMitre[Query mitre_attack<br/>by mitre_id]
        QueryMitre --> ExtractMitre[Extract:<br/>- technique_name<br/>- description]
        ExtractMitre --> Enrich[Add mitre_mapping<br/>to signature]
        Enrich --> LoopSigs
        
        LoopSigs -->|Done| EnrichedData[Enriched Analysis<br/>with MITRE data]
        
        EnrichedData --> ClearContext[🧹 Clear Ollama Context]
        ClearContext --> Stage4
        
        %% ===== STAGE 4: ANALYST AGENT REVIEW =====
        Stage4[/"🔷 STAGE 4: ANALYST AGENT REVIEW"/]
        
        Stage4 --> InitAnalyst[Initialize Analyst Agent<br/>Fresh LLM instance]
        InitAnalyst --> AnalystLoop{Analyst Iteration<br/>< max?}
        
        AnalystLoop -->|Yes| AnalystThink[Deep Dive Analysis:<br/>Threat context & impact]
        AnalystThink --> AnalystTool{Choose Tool}
        
        AnalystTool -->|ChromaQuery| AnalystChroma[Query MITRE techniques<br/>& log details]
        AnalystTool -->|WebSearch| AnalystWeb[Search CVEs &<br/>threat intelligence]
        
        AnalystChroma --> AnalystObserve[Observation:<br/>Enriched context]
        AnalystWeb --> AnalystObserve
        
        AnalystObserve --> AnalystLoop
        
        AnalystLoop -->|Max iterations<br/>or Final| AnalystResult[Final Analyst Report<br/>with recommendations]
        
        AnalystResult --> Stage5
        
        %% ===== STAGE 5: OUTPUT & NOTIFICATION =====
        Stage5[/"🔷 STAGE 5: OUTPUT & NOTIFICATION"/]
        
        Stage5 --> SaveJSON[Save to<br/>output/final_report.json]
        SaveJSON --> BuildOutput[Build final_output dict:<br/>- status: success<br/>- results<br/>- metrics]
        
        BuildOutput --> CheckEmail{Email<br/>enabled?}
        CheckEmail -->|Yes| SendEmail[Send HTML email<br/>to configured recipient]
        CheckEmail -->|No| SkipEmail[Skip email]
        
        SendEmail --> LogSummary
        SkipEmail --> LogSummary
        
        LogSummary[Log Pipeline Summary:<br/>- Signatures analyzed<br/>- MITRE techniques mapped<br/>- Output file path]
        
        LogSummary --> Success([✅ Pipeline Complete])
        
        %% ERROR HANDLING
        Error1 --> Failed
        Error2 --> Failed
        Failed([❌ Pipeline Failed])
        
        %% STYLING
        classDef stageClass fill:#4a90e2,stroke:#2e5c8a,stroke-width:3px,color:#fff
        classDef toolClass fill:#50c878,stroke:#2d7a4a,stroke-width:2px,color:#fff
        classDef dataClass fill:#f39c12,stroke:#c87f0a,stroke-width:2px,color:#fff
        classDef errorClass fill:#e74c3c,stroke:#c0392b,stroke-width:2px,color:#fff
        classDef successClass fill:#27ae60,stroke:#1e8449,stroke-width:3px,color:#fff
        
        class Stage1,Stage2,Stage3,Stage4,Stage5 stageClass
        class PG,CH,REL,AnalystChroma,AnalystWeb toolClass
        class BatchedData,ReactResult,EnrichedData,AnalystResult dataClass
        class Error1,Error2,Failed errorClass
        class Success successClass
    ```