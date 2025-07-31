package Model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CodeAnalysisRequest {
    
    @NotBlank(message = "Source code is required")
    private String sourceCode;
    
    @NotBlank(message = "Programming language is required")
    private String programmingLanguage;
    
    private String fileName;
    
    private String projectContext;
    
    @NotNull(message = "Analysis type is required")
    private AnalysisType analysisType;
    
    public enum AnalysisType {
        SECURITY_VULNERABILITIES,
        CODE_QUALITY,
        PERFORMANCE_ISSUES,
        COMPREHENSIVE
    }
} 