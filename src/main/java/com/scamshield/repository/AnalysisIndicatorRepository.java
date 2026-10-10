package com.scamshield.repository;

import com.scamshield.entity.AnalysisIndicator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AnalysisIndicatorRepository extends JpaRepository<AnalysisIndicator, Long> {

    @Query("SELECT ai.category, COUNT(ai) FROM AnalysisIndicator ai GROUP BY ai.category ORDER BY COUNT(ai) DESC")
    List<Object[]> countGroupedByCategory();
}
