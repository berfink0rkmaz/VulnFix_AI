package ServiceImpl;

import Model.dto.CodeAnalysisRequest;
import Model.dto.CodeAnalysisResponse;
import Model.entity.CodeAnalysis;
import Model.entity.User;
import Model.entity.Vulnerability;
import Repository.CodeAnalysisRepository;
import Repository.VulnerabilityRepository;
import Service.CodeAnalysisService;
import Service.GeminiAIService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Service
@Slf4j
@Transactional
public class CodeAnalysisServiceImpl implements CodeAnalysisService {
    
    @Autowired
    private CodeAnalysisRepository codeAnalysisRepository;
    
    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;
    
    @Autowired
    private GeminiAIService geminiAIService;
    
    @Override
    public CompletableFuture<CodeAnalysisResponse> analyzeCode(CodeAnalysisRequest request, User user) {
        return CompletableFuture.supplyAsync(() -> {
            long startTime = System.currentTimeMillis();
            
            try {
                // Create initial analysis record
                CodeAnalysis analysis = new CodeAnalysis();
                analysis.setSourceCode(request.getSourceCode());
                analysis.setProgrammingLanguage(request.getProgrammingLanguage());
                analysis.setStatus(CodeAnalysis.AnalysisStatus.PROCESSING);
                analysis.setUser(user);
                analysis.setCreatedAt(LocalDateTime.now());
                
                CodeAnalysis savedAnalysis = codeAnalysisRepository.save(analysis);
                
                // Perform AI analysis
                List<Vulnerability> vulnerabilities = geminiAIService
                    .analyzeCodeForVulnerabilities(request)
                    .join(); // Wait for completion
                
                // Save vulnerabilities
                for (Vulnerability vulnerability : vulnerabilities) {
                    vulnerability.setCodeAnalysis(savedAnalysis);
                    vulnerabilityRepository.save(vulnerability);
                }
                
                // Update analysis with results
                savedAnalysis.setVulnerabilities(vulnerabilities);
                savedAnalysis.setStatus(CodeAnalysis.AnalysisStatus.COMPLETED);
                savedAnalysis.setProcessingTimeMs(System.currentTimeMillis() - startTime);
                
                // Generate summary
                String summary = generateAnalysisSummary(vulnerabilities);
                savedAnalysis.setAnalysisSummary(summary);
                
                // Store AI response for debugging
                savedAnalysis.setAiResponse("Analysis completed successfully");
                
                codeAnalysisRepository.save(savedAnalysis);
                
                return convertToResponse(savedAnalysis);
                
            } catch (Exception e) {
                log.error("Error during code analysis", e);
                
                // Update analysis status to failed
                CodeAnalysis failedAnalysis = new CodeAnalysis();
                failedAnalysis.setSourceCode(request.getSourceCode());
                failedAnalysis.setProgrammingLanguage(request.getProgrammingLanguage());
                failedAnalysis.setStatus(CodeAnalysis.AnalysisStatus.FAILED);
                failedAnalysis.setUser(user);
                failedAnalysis.setProcessingTimeMs(System.currentTimeMillis() - startTime);
                failedAnalysis.setAnalysisSummary("Analysis failed: " + e.getMessage());
                failedAnalysis.setAiResponse("Error: " + e.getMessage());
                
                CodeAnalysis savedFailedAnalysis = codeAnalysisRepository.save(failedAnalysis);
                return convertToResponse(savedFailedAnalysis);
            }
        });
    }
    
    @Override
    public CodeAnalysisResponse getAnalysisById(Long analysisId, User user) {
        CodeAnalysis analysis = codeAnalysisRepository.findById(analysisId)
            .orElseThrow(() -> new RuntimeException("Analysis not found"));
        
        // Check if user has access to this analysis
        if (!analysis.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Access denied");
        }
        
        return convertToResponse(analysis);
    }
    
    @Override
    public Page<CodeAnalysisResponse> getUserAnalyses(User user, Pageable pageable) {
        Page<CodeAnalysis> analyses = codeAnalysisRepository.findByUser(user, pageable);
        return analyses.map(this::convertToResponse);
    }
    
    @Override
    public Page<CodeAnalysisResponse> getUserAnalysesByStatus(User user, CodeAnalysis.AnalysisStatus status, Pageable pageable) {
        Page<CodeAnalysis> analyses = codeAnalysisRepository.findByUserAndStatus(user, status, pageable);
        return analyses.map(this::convertToResponse);
    }
    
    @Override
    public CompletableFuture<String> generateCodeFix(Long vulnerabilityId, User user) {
        return CompletableFuture.supplyAsync(() -> {
            Vulnerability vulnerability = vulnerabilityRepository.findById(vulnerabilityId)
                .orElseThrow(() -> new RuntimeException("Vulnerability not found"));
            
            // Check if user has access to this vulnerability
            if (!vulnerability.getCodeAnalysis().getUser().getId().equals(user.getId())) {
                throw new RuntimeException("Access denied");
            }
            
            return geminiAIService.generateCodeFix(
                vulnerability.getVulnerableCode(),
                vulnerability.getType(),
                vulnerability.getCodeAnalysis().getProgrammingLanguage()
            ).join();
        });
    }
    
    @Override
    public CompletableFuture<String> getVulnerabilityExplanation(Long vulnerabilityId, User user) {
        return CompletableFuture.supplyAsync(() -> {
            Vulnerability vulnerability = vulnerabilityRepository.findById(vulnerabilityId)
                .orElseThrow(() -> new RuntimeException("Vulnerability not found"));
            
            // Check if user has access to this vulnerability
            if (!vulnerability.getCodeAnalysis().getUser().getId().equals(user.getId())) {
                throw new RuntimeException("Access denied");
            }
            
            return geminiAIService.generateVulnerabilityExplanation(
                vulnerability,
                vulnerability.getCodeAnalysis().getProgrammingLanguage()
            ).join();
        });
    }
    
    @Override
    public void deleteAnalysis(Long analysisId, User user) {
        CodeAnalysis analysis = codeAnalysisRepository.findById(analysisId)
            .orElseThrow(() -> new RuntimeException("Analysis not found"));
        
        // Check if user has access to this analysis
        if (!analysis.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Access denied");
        }
        
        codeAnalysisRepository.delete(analysis);
    }
    
    @Override
    public Map<String, Object> getVulnerabilityStatistics(User user) {
        Map<String, Object> statistics = new HashMap<>();
        
        // Get user's analyses
        List<CodeAnalysis> userAnalyses = codeAnalysisRepository.findRecentAnalysesByUser(user, Pageable.unpaged()).getContent();
        
        // Calculate statistics
        long totalAnalyses = userAnalyses.size();
        long completedAnalyses = userAnalyses.stream()
            .filter(a -> a.getStatus() == CodeAnalysis.AnalysisStatus.COMPLETED)
            .count();
        
        // Get all vulnerabilities for the user
        List<Vulnerability> allVulnerabilities = userAnalyses.stream()
            .flatMap(analysis -> analysis.getVulnerabilities().stream())
            .collect(Collectors.toList());
        
        // Count by severity
        Map<Vulnerability.Severity, Long> severityCounts = allVulnerabilities.stream()
            .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));
        
        // Count by type
        Map<Vulnerability.VulnerabilityType, Long> typeCounts = allVulnerabilities.stream()
            .collect(Collectors.groupingBy(Vulnerability::getType, Collectors.counting()));
        
        statistics.put("totalAnalyses", totalAnalyses);
        statistics.put("completedAnalyses", completedAnalyses);
        statistics.put("totalVulnerabilities", allVulnerabilities.size());
        statistics.put("severityDistribution", severityCounts);
        statistics.put("typeDistribution", typeCounts);
        statistics.put("averageProcessingTime", userAnalyses.stream()
            .filter(a -> a.getProcessingTimeMs() != null)
            .mapToLong(CodeAnalysis::getProcessingTimeMs)
            .average()
            .orElse(0.0));
        
        return statistics;
    }
    
    private String generateAnalysisSummary(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            return "No security vulnerabilities detected in the analyzed code.";
        }
        
        long criticalCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL)
            .count();
        long highCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH)
            .count();
        long mediumCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM)
            .count();
        long lowCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == Vulnerability.Severity.LOW)
            .count();
        
        return String.format("Analysis completed. Found %d vulnerabilities: %d critical, %d high, %d medium, %d low.",
            vulnerabilities.size(), criticalCount, highCount, mediumCount, lowCount);
    }
    
    private CodeAnalysisResponse convertToResponse(CodeAnalysis analysis) {
        CodeAnalysisResponse response = new CodeAnalysisResponse();
        response.setId(analysis.getId());
        response.setAnalysisSummary(analysis.getAnalysisSummary());
        response.setStatus(analysis.getStatus());
        response.setProcessingTimeMs(analysis.getProcessingTimeMs());
        response.setCreatedAt(analysis.getCreatedAt());
        response.setUpdatedAt(analysis.getUpdatedAt());
        
        // Convert vulnerabilities to DTOs
        List<CodeAnalysisResponse.VulnerabilityDto> vulnerabilityDtos = analysis.getVulnerabilities().stream()
            .map(this::convertVulnerabilityToDto)
            .collect(Collectors.toList());
        
        response.setVulnerabilities(vulnerabilityDtos);
        
        return response;
    }
    
    private CodeAnalysisResponse.VulnerabilityDto convertVulnerabilityToDto(Vulnerability vulnerability) {
        CodeAnalysisResponse.VulnerabilityDto dto = new CodeAnalysisResponse.VulnerabilityDto();
        dto.setId(vulnerability.getId());
        dto.setTitle(vulnerability.getTitle());
        dto.setDescription(vulnerability.getDescription());
        dto.setSeverity(vulnerability.getSeverity());
        dto.setType(vulnerability.getType());
        dto.setLineNumber(vulnerability.getLineNumber());
        dto.setColumnNumber(vulnerability.getColumnNumber());
        dto.setVulnerableCode(vulnerability.getVulnerableCode());
        dto.setFixedCode(vulnerability.getFixedCode());
        dto.setCweId(vulnerability.getCweId());
        dto.setCvssScore(vulnerability.getCvssScore());
        dto.setRecommendation(vulnerability.getRecommendation());
        
        return dto;
    }
} 