package com.scamshield.controller;

import com.scamshield.dto.AdminAnalyticsResponse;
import com.scamshield.dto.ReportResponse;
import com.scamshield.dto.UpdateReportStatusRequest;
import com.scamshield.dto.UserSummaryDto;
import com.scamshield.entity.AuditLog;
import com.scamshield.service.AuditLogService;
import com.scamshield.service.AuthService;
import com.scamshield.service.InsightsService;
import com.scamshield.service.ReportService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminController {

    private final ReportService reportService;
    private final AuthService authService;
    private final InsightsService insightsService;
    private final AuditLogService auditLogService;

    public AdminController(ReportService reportService,
                           AuthService authService,
                           InsightsService insightsService,
                           AuditLogService auditLogService) {
        this.reportService = reportService;
        this.authService = authService;
        this.insightsService = insightsService;
        this.auditLogService = auditLogService;
    }

    @GetMapping("/reports")
    public ResponseEntity<List<ReportResponse>> getAllReports() {
        return ResponseEntity.ok(reportService.getAllReports());
    }

    @PatchMapping("/reports/{id}/status")
    public ResponseEntity<ReportResponse> updateReportStatus(
            @PathVariable Long id,
            @Valid @RequestBody UpdateReportStatusRequest request,
            HttpServletRequest servletRequest) {

        String clientIp = extractClientIp(servletRequest);
        ReportResponse response = reportService.updateReportStatus(id, request, clientIp);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserSummaryDto>> getAllUsers() {
        return ResponseEntity.ok(authService.getAllUsers());
    }

    @PatchMapping("/users/{id}/toggle-status")
    public ResponseEntity<UserSummaryDto> toggleUserStatus(
            @PathVariable Long id,
            HttpServletRequest servletRequest) {

        String clientIp = extractClientIp(servletRequest);
        return ResponseEntity.ok(authService.toggleUserStatus(id, clientIp));
    }

    @GetMapping("/analytics")
    public ResponseEntity<AdminAnalyticsResponse> getAdminAnalytics() {
        return ResponseEntity.ok(insightsService.getAdminAnalytics());
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<List<AuditLog>> getAuditLogs() {
        return ResponseEntity.ok(auditLogService.getRecentLogs());
    }

    private String extractClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
