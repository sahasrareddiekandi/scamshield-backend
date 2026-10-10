package com.scamshield.dto;

import com.scamshield.entity.ReportStatus;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class UpdateReportStatusRequest {

    @NotNull(message = "Status is required")
    private ReportStatus status;

    @Size(max = 2000, message = "Admin notes exceeded length")
    private String adminNotes;

    public UpdateReportStatusRequest() {}

    public ReportStatus getStatus() {
        return status;
    }

    public void setStatus(ReportStatus status) {
        this.status = status;
    }

    public String getAdminNotes() {
        return adminNotes;
    }

    public void setAdminNotes(String adminNotes) {
        this.adminNotes = adminNotes;
    }
}
