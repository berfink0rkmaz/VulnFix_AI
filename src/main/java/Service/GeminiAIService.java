package Service;

import Model.dto.CodeAnalysisRequest;
import Model.entity.Vulnerability;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface GeminiAIService {
    
    /**
     * Analyzes source code for security vulnerabilities using Google Gemini AI
     * @param request The code analysis request containing source code and metadata
     * @return A CompletableFuture containing the list of detected vulnerabilities
     */
    CompletableFuture<List<Vulnerability>> analyzeCodeForVulnerabilities(CodeAnalysisRequest request);
    
    /**
     * Generates fixed code suggestions for detected vulnerabilities
     * @param vulnerableCode The original vulnerable code
     * @param vulnerabilityType The type of vulnerability detected
     * @param programmingLanguage The programming language of the code
     * @return A CompletableFuture containing the suggested fixed code
     */
    CompletableFuture<String> generateCodeFix(String vulnerableCode, 
                                            Vulnerability.VulnerabilityType vulnerabilityType, 
                                            String programmingLanguage);
    
    /**
     * Provides detailed explanation and recommendations for a vulnerability
     * @param vulnerability The vulnerability to explain
     * @param programmingLanguage The programming language context
     * @return A CompletableFuture containing the detailed explanation
     */
    CompletableFuture<String> generateVulnerabilityExplanation(Vulnerability vulnerability, 
                                                              String programmingLanguage);
    
    /**
     * Checks if the Gemini AI service is available and properly configured
     * @return true if the service is available, false otherwise
     */
    boolean isServiceAvailable();
} 