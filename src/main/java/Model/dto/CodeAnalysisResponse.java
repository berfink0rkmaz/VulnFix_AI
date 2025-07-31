package Model.dto;

import Model.entity.CodeAnalysis;
import Model.entity.Vulnerability;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CodeAnalysisResponse {
    
    private Long id;
    private String analysisSummary;
    private CodeAnalysis.AnalysisStatus status;
    private List<VulnerabilityDto> vulnerabilities;
    private Long processingTimeMs;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VulnerabilityDto {
        private Long id;
        private String title;
        private String description;
        private Vulnerability.Severity severity;
        private Vulnerability.VulnerabilityType type;
        private Integer lineNumber;
        private Integer columnNumber;
        private String vulnerableCode;
        private String fixedCode;
        private String cweId;
        private Double cvssScore;
        private String recommendation;
    }
} 