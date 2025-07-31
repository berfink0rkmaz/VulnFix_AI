package Service;

import Model.dto.CodeAnalysisRequest;
import Model.dto.CodeAnalysisResponse;
import Model.entity.CodeAnalysis;
import Model.entity.User;
import Model.entity.Vulnerability;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface CodeAnalysisService {
    
    /**
     * Initiates a new code analysis for security vulnerabilities
     * @param request The code analysis request
     * @param user The user requesting the analysis
     * @return A CompletableFuture containing the analysis response
     */
    CompletableFuture<CodeAnalysisResponse> analyzeCode(CodeAnalysisRequest request, User user);
    
    /**
     * Retrieves a specific code analysis by ID
     * @param analysisId The ID of the analysis to retrieve
     * @param user The user requesting the analysis
     * @return The code analysis response
     */
    CodeAnalysisResponse getAnalysisById(Long analysisId, User user);
    
    /**
     * Retrieves all analyses for a user with pagination
     * @param user The user whose analyses to retrieve
     * @param pageable Pagination parameters
     * @return A page of code analysis responses
     */
    Page<CodeAnalysisResponse> getUserAnalyses(User user, Pageable pageable);
    
    /**
     * Retrieves analyses by status for a user
     * @param user The user whose analyses to retrieve
     * @param status The status to filter by
     * @param pageable Pagination parameters
     * @return A page of code analysis responses
     */
    Page<CodeAnalysisResponse> getUserAnalysesByStatus(User user, CodeAnalysis.AnalysisStatus status, Pageable pageable);
    
    /**
     * Generates a code fix for a specific vulnerability
     * @param vulnerabilityId The ID of the vulnerability
     * @param user The user requesting the fix
     * @return A CompletableFuture containing the suggested fix
     */
    CompletableFuture<String> generateCodeFix(Long vulnerabilityId, User user);
    
    /**
     * Gets detailed explanation for a vulnerability
     * @param vulnerabilityId The ID of the vulnerability
     * @param user The user requesting the explanation
     * @return A CompletableFuture containing the detailed explanation
     */
    CompletableFuture<String> getVulnerabilityExplanation(Long vulnerabilityId, User user);
    
    /**
     * Deletes a code analysis
     * @param analysisId The ID of the analysis to delete
     * @param user The user requesting the deletion
     */
    void deleteAnalysis(Long analysisId, User user);
    
    /**
     * Gets vulnerability statistics for a user
     * @param user The user to get statistics for
     * @return A map containing vulnerability statistics
     */
    java.util.Map<String, Object> getVulnerabilityStatistics(User user);
} 