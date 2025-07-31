package ServiceImpl;

import Model.dto.CodeAnalysisRequest;
import Model.entity.Vulnerability;
import Service.GeminiAIService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Slf4j
public class GeminiAIServiceImpl implements GeminiAIService {
    
    @Value("${gemini.api.key}")
    private String apiKey;
    
    @Value("${gemini.api.url}")
    private String apiUrl;
    
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    
    public GeminiAIServiceImpl() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }
    
    @Override
    public CompletableFuture<List<Vulnerability>> analyzeCodeForVulnerabilities(CodeAnalysisRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String prompt = buildVulnerabilityAnalysisPrompt(request);
                String response = callGeminiAPI(prompt);
                return parseVulnerabilitiesFromResponse(response, request.getProgrammingLanguage());
            } catch (Exception e) {
                log.error("Error analyzing code for vulnerabilities", e);
                return new ArrayList<>();
            }
        });
    }
    
    @Override
    public CompletableFuture<String> generateCodeFix(String vulnerableCode, 
                                                   Vulnerability.VulnerabilityType vulnerabilityType, 
                                                   String programmingLanguage) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String prompt = buildCodeFixPrompt(vulnerableCode, vulnerabilityType, programmingLanguage);
                return callGeminiAPI(prompt);
            } catch (Exception e) {
                log.error("Error generating code fix", e);
                return "Unable to generate fix at this time.";
            }
        });
    }
    
    @Override
    public CompletableFuture<String> generateVulnerabilityExplanation(Vulnerability vulnerability, 
                                                                     String programmingLanguage) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String prompt = buildExplanationPrompt(vulnerability, programmingLanguage);
                return callGeminiAPI(prompt);
            } catch (Exception e) {
                log.error("Error generating vulnerability explanation", e);
                return "Unable to generate explanation at this time.";
            }
        });
    }
    
    @Override
    public boolean isServiceAvailable() {
        try {
            return apiKey != null && !apiKey.equals("your-gemini-api-key-here") && !apiKey.isEmpty();
        } catch (Exception e) {
            log.error("Error checking service availability", e);
            return false;
        }
    }
    
    private String buildVulnerabilityAnalysisPrompt(CodeAnalysisRequest request) {
        return String.format("""
            You are a security expert analyzing code for vulnerabilities. Please analyze the following %s code and identify any security vulnerabilities.
            
            Code to analyze:
            ```%s
            %s
            ```
            
            Context: %s
            
            Please provide your analysis in the following JSON format:
            {
                "vulnerabilities": [
                    {
                        "title": "Vulnerability title",
                        "description": "Detailed description",
                        "severity": "LOW|MEDIUM|HIGH|CRITICAL",
                        "type": "SQL_INJECTION|XSS|CSRF|BUFFER_OVERFLOW|INSECURE_DESERIALIZATION|BROKEN_AUTHENTICATION|SENSITIVE_DATA_EXPOSURE|MISSING_FUNCTION_LEVEL_ACCESS_CONTROL|USING_COMPONENTS_WITH_KNOWN_VULNERABILITIES|INSUFFICIENT_LOGGING_AND_MONITORING|INSECURE_DIRECT_OBJECT_REFERENCES|SECURITY_MISCONFIGURATION|OTHER",
                        "lineNumber": line_number,
                        "columnNumber": column_number,
                        "vulnerableCode": "the vulnerable code snippet",
                        "cweId": "CWE-XXX",
                        "cvssScore": score_between_0_and_10,
                        "recommendation": "How to fix this vulnerability"
                    }
                ]
            }
            
            Focus on identifying real security vulnerabilities and provide actionable recommendations.
            """, 
            request.getProgrammingLanguage(),
            request.getProgrammingLanguage(),
            request.getSourceCode(),
            request.getProjectContext() != null ? request.getProjectContext() : "No additional context provided"
        );
    }
    
    private String buildCodeFixPrompt(String vulnerableCode, 
                                    Vulnerability.VulnerabilityType vulnerabilityType, 
                                    String programmingLanguage) {
        return String.format("""
            You are a security expert. Please provide a secure code fix for the following vulnerable %s code.
            
            Vulnerability Type: %s
            Vulnerable Code:
            ```%s
            %s
            ```
            
            Please provide only the corrected code without any explanations or markdown formatting.
            """,
            programmingLanguage,
            vulnerabilityType.name(),
            programmingLanguage,
            vulnerableCode
        );
    }
    
    private String buildExplanationPrompt(Vulnerability vulnerability, String programmingLanguage) {
        return String.format("""
            Please provide a detailed explanation of the following security vulnerability in %s:
            
            Title: %s
            Description: %s
            Severity: %s
            Type: %s
            CWE ID: %s
            CVSS Score: %s
            
            Please explain:
            1. What this vulnerability means
            2. How it can be exploited
            3. Real-world examples
            4. Best practices to prevent it
            5. Additional security considerations
            """,
            programmingLanguage,
            vulnerability.getTitle(),
            vulnerability.getDescription(),
            vulnerability.getSeverity(),
            vulnerability.getType(),
            vulnerability.getCweId(),
            vulnerability.getCvssScore()
        );
    }
    
    private String callGeminiAPI(String prompt) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("x-goog-api-key", apiKey);
            
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("contents", Arrays.asList(
                Map.of("parts", Arrays.asList(
                    Map.of("text", prompt)
                ))
            ));
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            ResponseEntity<String> response = restTemplate.exchange(apiUrl, HttpMethod.POST, entity, String.class);
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode responseJson = objectMapper.readTree(response.getBody());
                return extractTextFromResponse(responseJson);
            } else {
                log.error("Gemini API returned error: {}", response.getStatusCode());
                return "Error: Unable to process request";
            }
        } catch (Exception e) {
            log.error("Error calling Gemini API", e);
            return "Error: " + e.getMessage();
        }
    }
    
    private String extractTextFromResponse(JsonNode responseJson) {
        try {
            JsonNode candidates = responseJson.get("candidates");
            if (candidates != null && candidates.isArray() && candidates.size() > 0) {
                JsonNode content = candidates.get(0).get("content");
                if (content != null) {
                    JsonNode parts = content.get("parts");
                    if (parts != null && parts.isArray() && parts.size() > 0) {
                        return parts.get(0).get("text").asText();
                    }
                }
            }
            return "No response content found";
        } catch (Exception e) {
            log.error("Error extracting text from Gemini response", e);
            return "Error parsing response";
        }
    }
    
    private List<Vulnerability> parseVulnerabilitiesFromResponse(String response, String programmingLanguage) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            // Try to parse as JSON first
            if (response.contains("\"vulnerabilities\"")) {
                JsonNode responseJson = objectMapper.readTree(response);
                JsonNode vulnerabilitiesNode = responseJson.get("vulnerabilities");
                
                if (vulnerabilitiesNode != null && vulnerabilitiesNode.isArray()) {
                    for (JsonNode vulnNode : vulnerabilitiesNode) {
                        Vulnerability vulnerability = new Vulnerability();
                        vulnerability.setTitle(vulnNode.get("title").asText());
                        vulnerability.setDescription(vulnNode.get("description").asText());
                        vulnerability.setSeverity(Vulnerability.Severity.valueOf(vulnNode.get("severity").asText()));
                        vulnerability.setType(Vulnerability.VulnerabilityType.valueOf(vulnNode.get("type").asText()));
                        
                        if (vulnNode.has("lineNumber")) {
                            vulnerability.setLineNumber(vulnNode.get("lineNumber").asInt());
                        }
                        if (vulnNode.has("columnNumber")) {
                            vulnerability.setColumnNumber(vulnNode.get("columnNumber").asInt());
                        }
                        if (vulnNode.has("vulnerableCode")) {
                            vulnerability.setVulnerableCode(vulnNode.get("vulnerableCode").asText());
                        }
                        if (vulnNode.has("cweId")) {
                            vulnerability.setCweId(vulnNode.get("cweId").asText());
                        }
                        if (vulnNode.has("cvssScore")) {
                            vulnerability.setCvssScore(vulnNode.get("cvssScore").asDouble());
                        }
                        if (vulnNode.has("recommendation")) {
                            vulnerability.setRecommendation(vulnNode.get("recommendation").asText());
                        }
                        
                        vulnerabilities.add(vulnerability);
                    }
                }
            } else {
                // Fallback: try to extract vulnerabilities from text response
                vulnerabilities.addAll(extractVulnerabilitiesFromText(response, programmingLanguage));
            }
        } catch (Exception e) {
            log.error("Error parsing vulnerabilities from response", e);
            // Fallback: try to extract vulnerabilities from text response
            vulnerabilities.addAll(extractVulnerabilitiesFromText(response, programmingLanguage));
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> extractVulnerabilitiesFromText(String response, String programmingLanguage) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Simple pattern matching for common vulnerability indicators
        Pattern pattern = Pattern.compile("(?i)(sql injection|xss|csrf|buffer overflow|insecure|vulnerability|security issue)");
        Matcher matcher = pattern.matcher(response);
        
        if (matcher.find()) {
            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setTitle("Potential Security Issue Detected");
            vulnerability.setDescription("AI analysis identified potential security concerns in the code.");
            vulnerability.setSeverity(Vulnerability.Severity.MEDIUM);
            vulnerability.setType(Vulnerability.VulnerabilityType.OTHER);
            vulnerability.setRecommendation("Review the code manually for security best practices.");
            vulnerabilities.add(vulnerability);
        }
        
        return vulnerabilities;
    }
} 