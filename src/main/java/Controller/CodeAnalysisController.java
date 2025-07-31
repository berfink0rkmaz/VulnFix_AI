package Controller;

import Model.dto.CodeAnalysisRequest;
import Model.dto.CodeAnalysisResponse;
import Model.entity.CodeAnalysis;
import Model.entity.User;
import Service.CodeAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/analysis")
@Tag(name = "Code Analysis", description = "APIs for analyzing code for security vulnerabilities")
@Slf4j
@Validated
public class CodeAnalysisController {
    
    @Autowired
    private CodeAnalysisService codeAnalysisService;
    
    @PostMapping
    @Operation(
        summary = "Analyze code for security vulnerabilities",
        description = "Submits source code for AI-powered security vulnerability analysis using Google Gemini"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "202", description = "Analysis accepted and processing started",
            content = @Content(schema = @Schema(implementation = CodeAnalysisResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request data"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<CompletableFuture<CodeAnalysisResponse>> analyzeCode(
            @Valid @RequestBody CodeAnalysisRequest request,
            @AuthenticationPrincipal User user) {
        
        log.info("Received code analysis request from user: {}", user.getUsername());
        
        CompletableFuture<CodeAnalysisResponse> future = codeAnalysisService.analyzeCode(request, user);
        
        return ResponseEntity.accepted().body(future);
    }
    
    @GetMapping("/{analysisId}")
    @Operation(
        summary = "Get analysis results by ID",
        description = "Retrieves the results of a specific code analysis"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Analysis found",
            content = @Content(schema = @Schema(implementation = CodeAnalysisResponse.class))),
        @ApiResponse(responseCode = "404", description = "Analysis not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    public ResponseEntity<CodeAnalysisResponse> getAnalysisById(
            @Parameter(description = "ID of the analysis to retrieve") 
            @PathVariable Long analysisId,
            @AuthenticationPrincipal User user) {
        
        try {
            CodeAnalysisResponse response = codeAnalysisService.getAnalysisById(analysisId, user);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            } else if (e.getMessage().contains("Access denied")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            throw e;
        }
    }
    
    @GetMapping
    @Operation(
        summary = "Get user's analyses",
        description = "Retrieves paginated list of code analyses for the authenticated user"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Analyses retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<Page<CodeAnalysisResponse>> getUserAnalyses(
            @Parameter(description = "Page number (0-based)") 
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size") 
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Filter by analysis status") 
            @RequestParam(required = false) CodeAnalysis.AnalysisStatus status,
            @AuthenticationPrincipal User user) {
        
        Pageable pageable = PageRequest.of(page, size);
        
        Page<CodeAnalysisResponse> analyses;
        if (status != null) {
            analyses = codeAnalysisService.getUserAnalysesByStatus(user, status, pageable);
        } else {
            analyses = codeAnalysisService.getUserAnalyses(user, pageable);
        }
        
        return ResponseEntity.ok(analyses);
    }
    
    @GetMapping("/{analysisId}/vulnerabilities/{vulnerabilityId}/fix")
    @Operation(
        summary = "Generate code fix for vulnerability",
        description = "Generates a suggested code fix for a specific vulnerability using AI"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Code fix generated successfully"),
        @ApiResponse(responseCode = "404", description = "Vulnerability not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    public ResponseEntity<CompletableFuture<String>> generateCodeFix(
            @Parameter(description = "ID of the analysis") 
            @PathVariable Long analysisId,
            @Parameter(description = "ID of the vulnerability") 
            @PathVariable Long vulnerabilityId,
            @AuthenticationPrincipal User user) {
        
        CompletableFuture<String> future = codeAnalysisService.generateCodeFix(vulnerabilityId, user);
        return ResponseEntity.ok(future);
    }
    
    @GetMapping("/{analysisId}/vulnerabilities/{vulnerabilityId}/explanation")
    @Operation(
        summary = "Get vulnerability explanation",
        description = "Generates a detailed explanation of a specific vulnerability"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Explanation generated successfully"),
        @ApiResponse(responseCode = "404", description = "Vulnerability not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    public ResponseEntity<CompletableFuture<String>> getVulnerabilityExplanation(
            @Parameter(description = "ID of the analysis") 
            @PathVariable Long analysisId,
            @Parameter(description = "ID of the vulnerability") 
            @PathVariable Long vulnerabilityId,
            @AuthenticationPrincipal User user) {
        
        CompletableFuture<String> future = codeAnalysisService.getVulnerabilityExplanation(vulnerabilityId, user);
        return ResponseEntity.ok(future);
    }
    
    @DeleteMapping("/{analysisId}")
    @Operation(
        summary = "Delete analysis",
        description = "Deletes a specific code analysis"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "Analysis deleted successfully"),
        @ApiResponse(responseCode = "404", description = "Analysis not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    public ResponseEntity<Void> deleteAnalysis(
            @Parameter(description = "ID of the analysis to delete") 
            @PathVariable Long analysisId,
            @AuthenticationPrincipal User user) {
        
        try {
            codeAnalysisService.deleteAnalysis(analysisId, user);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            } else if (e.getMessage().contains("Access denied")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            throw e;
        }
    }
    
    @GetMapping("/statistics")
    @Operation(
        summary = "Get vulnerability statistics",
        description = "Retrieves vulnerability statistics for the authenticated user"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Statistics retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<Map<String, Object>> getStatistics(@AuthenticationPrincipal User user) {
        Map<String, Object> statistics = codeAnalysisService.getVulnerabilityStatistics(user);
        return ResponseEntity.ok(statistics);
    }
} 