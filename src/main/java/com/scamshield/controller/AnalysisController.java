package com.scamshield.controller;

import com.scamshield.dto.AnalysisResponse;
import com.scamshield.dto.MessageAnalysisRequest;
import com.scamshield.dto.UrlAnalysisRequest;
import com.scamshield.exception.RateLimitExceededException;
import com.scamshield.service.AnalysisService;
import com.scamshield.service.RateLimiterService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class AnalysisController {

    private final AnalysisService analysisService;
    private final RateLimiterService rateLimiterService;

    public AnalysisController(AnalysisService analysisService, RateLimiterService rateLimiterService) {
        this.analysisService = analysisService;
        this.rateLimiterService = rateLimiterService;
    }

    @PostMapping("/analyze/message")
    public ResponseEntity<AnalysisResponse> analyzeMessage(
            @Valid @RequestBody MessageAnalysisRequest request,
            HttpServletRequest servletRequest) {

        String clientIp = extractClientIp(servletRequest);
        if (!rateLimiterService.tryAcquire(clientIp)) {
            throw new RateLimitExceededException("Too many analysis requests. Rate limit is 30 requests per minute.");
        }

        AnalysisResponse response = analysisService.analyzeMessage(request.getMessage(), clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/analyze/url")
    public ResponseEntity<AnalysisResponse> analyzeUrl(
            @Valid @RequestBody UrlAnalysisRequest request,
            HttpServletRequest servletRequest) {

        String clientIp = extractClientIp(servletRequest);
        if (!rateLimiterService.tryAcquire(clientIp)) {
            throw new RateLimitExceededException("Too many analysis requests. Rate limit is 30 requests per minute.");
        }

        AnalysisResponse response = analysisService.analyzeUrl(request.getUrl(), clientIp);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/analyses")
    public ResponseEntity<List<AnalysisResponse>> getUserAnalyses() {
        return ResponseEntity.ok(analysisService.getUserAnalyses());
    }

    @GetMapping("/analyses/paged")
    public ResponseEntity<Page<AnalysisResponse>> getUserAnalysesPaged(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return ResponseEntity.ok(analysisService.getUserAnalysesPaged(pageRequest));
    }

    @GetMapping("/analyses/{id}")
    public ResponseEntity<AnalysisResponse> getAnalysisById(@PathVariable Long id) {
        return ResponseEntity.ok(analysisService.getAnalysisById(id));
    }

    private String extractClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
