package com.scamshield.repository;

import com.scamshield.entity.Analysis;
import com.scamshield.entity.ContentType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AnalysisRepository extends JpaRepository<Analysis, Long> {
    Optional<Analysis> findTopByContentHashOrderByCreatedAtDesc(String contentHash);
    List<Analysis> findByUserOrderByCreatedAtDesc(User user);
    Page<Analysis> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);
    List<Analysis> findTop10ByOrderByCreatedAtDesc();
    
    long countByRiskLevel(RiskLevel riskLevel);
    long countByContentType(ContentType contentType);

    @Query("SELECT a.scamType, COUNT(a) FROM Analysis a WHERE a.scamType IS NOT NULL GROUP BY a.scamType ORDER BY COUNT(a) DESC")
    List<Object[]> countGroupedByScamType();

    @Query("SELECT AVG(a.riskScore) FROM Analysis a")
    Double calculateAverageRiskScore();
}
