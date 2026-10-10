package com.scamshield.service;

import com.scamshield.dto.ReportRequest;
import com.scamshield.dto.ReportResponse;
import com.scamshield.dto.UpdateReportStatusRequest;
import com.scamshield.entity.ReportedContent;
import com.scamshield.entity.ReportStatus;
import com.scamshield.entity.User;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.repository.ReportedContentRepository;
import com.scamshield.repository.UserRepository;
import com.scamshield.security.SecurityUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ReportService {

    private final ReportedContentRepository reportedContentRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    public ReportService(ReportedContentRepository reportedContentRepository,
                         UserRepository userRepository,
                         AuditLogService auditLogService) {
        this.reportedContentRepository = reportedContentRepository;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public ReportResponse submitReport(ReportRequest request, String clientIp) {
        ReportedContent report = new ReportedContent();
        report.setContent(request.getContent().trim());
        report.setContentType(request.getContentType());
        report.setScamType(request.getScamType() != null ? request.getScamType().trim() : "Unspecified");
        report.setDescription(request.getDescription());
        report.setStatus(ReportStatus.PENDING);

        Optional<User> currentUser = SecurityUtils.getCurrentUserEmail().flatMap(userRepository::findByEmail);
        currentUser.ifPresent(report::setUser);

        ReportedContent saved = reportedContentRepository.save(report);

        String actor = currentUser.map(User::getEmail).orElse("ANONYMOUS");
        auditLogService.log("REPORT_SUBMITTED", actor, clientIp,
                "Report ID " + saved.getId() + " filed for " + saved.getContentType());

        return mapToResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<ReportResponse> getAllReports() {
        return reportedContentRepository.findAllByOrderByReportedAtDesc()
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ReportResponse> getUserReports() {
        Optional<User> currentUser = SecurityUtils.getCurrentUserEmail().flatMap(userRepository::findByEmail);
        if (currentUser.isEmpty()) {
            return List.of();
        }
        return reportedContentRepository.findByUserOrderByReportedAtDesc(currentUser.get())
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public ReportResponse updateReportStatus(Long id, UpdateReportStatusRequest request, String clientIp) {
        ReportedContent report = reportedContentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Report not found with ID: " + id));

        report.setStatus(request.getStatus());
        if (request.getAdminNotes() != null) {
            report.setAdminNotes(request.getAdminNotes());
        }
        if (request.getStatus() != ReportStatus.PENDING) {
            report.setResolvedAt(LocalDateTime.now());
        }

        ReportedContent updated = reportedContentRepository.save(report);

        String actor = SecurityUtils.getCurrentUserEmail().orElse("ADMIN");
        auditLogService.log("REPORT_MODERATION", actor, clientIp,
                "Report " + id + " updated to " + request.getStatus());

        return mapToResponse(updated);
    }

    private ReportResponse mapToResponse(ReportedContent entity) {
        ReportResponse dto = new ReportResponse();
        dto.setId(entity.getId());
        dto.setContent(entity.getContent());
        dto.setContentType(entity.getContentType());
        dto.setScamType(entity.getScamType());
        dto.setDescription(entity.getDescription());
        dto.setStatus(entity.getStatus());
        dto.setAdminNotes(entity.getAdminNotes());
        dto.setReportedAt(entity.getReportedAt());
        dto.setResolvedAt(entity.getResolvedAt());
        if (entity.getUser() != null) {
            dto.setReporterEmail(entity.getUser().getEmail());
        } else {
            dto.setReporterEmail("Anonymous Community Contributor");
        }
        return dto;
    }
}
