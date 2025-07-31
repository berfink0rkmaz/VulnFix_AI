package Repository;

import Model.entity.CodeAnalysis;
import Model.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CodeAnalysisRepository extends JpaRepository<CodeAnalysis, Long> {
    
    Page<CodeAnalysis> findByUser(User user, Pageable pageable);
    
    Page<CodeAnalysis> findByUserAndStatus(User user, CodeAnalysis.AnalysisStatus status, Pageable pageable);
    
    List<CodeAnalysis> findByStatus(CodeAnalysis.AnalysisStatus status);
    
    @Query("SELECT ca FROM CodeAnalysis ca WHERE ca.createdAt >= :startDate AND ca.createdAt <= :endDate")
    List<CodeAnalysis> findByDateRange(@Param("startDate") LocalDateTime startDate, 
                                      @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT ca FROM CodeAnalysis ca WHERE ca.programmingLanguage = :language")
    List<CodeAnalysis> findByProgrammingLanguage(@Param("language") String language);
    
    @Query("SELECT COUNT(ca) FROM CodeAnalysis ca WHERE ca.status = :status")
    long countByStatus(@Param("status") CodeAnalysis.AnalysisStatus status);
    
    @Query("SELECT ca FROM CodeAnalysis ca WHERE ca.user = :user ORDER BY ca.createdAt DESC")
    List<CodeAnalysis> findRecentAnalysesByUser(@Param("user") User user, Pageable pageable);
} 