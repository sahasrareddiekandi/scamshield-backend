package com.scamshield.service;

import com.scamshield.entity.AuditLog;
import com.scamshield.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuditLogService {

    private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void log(String action, String performedBy, String ipAddress, String details) {
        try {
            AuditLog auditLog = new AuditLog(action, performedBy, ipAddress, details);
            auditLogRepository.save(auditLog);
            logger.info("AUDIT: action={}, performedBy={}, ip={}", action, performedBy, ipAddress);
        } catch (Exception e) {
            logger.warn("Failed to record audit log: {}", e.getMessage());
        }
    }

    public List<AuditLog> getRecentLogs() {
        return auditLogRepository.findTop50ByOrderByTimestampDesc();
    }

    public long getTotalLogs() {
        return auditLogRepository.count();
    }
}
