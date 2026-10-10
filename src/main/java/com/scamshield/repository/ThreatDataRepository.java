package com.scamshield.repository;

import com.scamshield.entity.ThreatData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ThreatDataRepository extends JpaRepository<ThreatData, Long> {
    Optional<ThreatData> findByPattern(String pattern);
    List<ThreatData> findTop20ByOrderByDetectionCountDesc();
}
