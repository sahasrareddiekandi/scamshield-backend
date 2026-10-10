package com.scamshield.repository;

import com.scamshield.entity.ReportStatus;
import com.scamshield.entity.ReportedContent;
import com.scamshield.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ReportedContentRepository extends JpaRepository<ReportedContent, Long> {
    List<ReportedContent> findAllByOrderByReportedAtDesc();
    List<ReportedContent> findByStatusOrderByReportedAtDesc(ReportStatus status);
    List<ReportedContent> findByUserOrderByReportedAtDesc(User user);
    long countByStatus(ReportStatus status);
}
