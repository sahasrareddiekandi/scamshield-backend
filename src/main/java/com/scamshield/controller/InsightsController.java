package com.scamshield.controller;

import com.scamshield.dto.InsightsResponse;
import com.scamshield.service.InsightsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/insights")
public class InsightsController {

    private final InsightsService insightsService;

    public InsightsController(InsightsService insightsService) {
        this.insightsService = insightsService;
    }

    @GetMapping
    public ResponseEntity<InsightsResponse> getInsights() {
        return ResponseEntity.ok(insightsService.getPublicInsights());
    }
}
