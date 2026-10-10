package com.scamshield.service;

import com.scamshield.dto.AuthRequest;
import com.scamshield.dto.AuthResponse;
import com.scamshield.dto.RegisterRequest;
import com.scamshield.dto.UserSummaryDto;
import com.scamshield.entity.Role;
import com.scamshield.entity.User;
import com.scamshield.exception.BadRequestException;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.repository.UserRepository;
import com.scamshield.security.JwtTokenProvider;
import com.scamshield.security.SecurityUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final AuditLogService auditLogService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtTokenProvider tokenProvider,
                       AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request, String clientIp) {
        String cleanEmail = request.getEmail().trim().toLowerCase();
        if (userRepository.existsByEmail(cleanEmail)) {
            throw new BadRequestException("An account with email " + cleanEmail + " already exists.");
        }

        User user = new User();
        user.setEmail(cleanEmail);
        user.setFullName(request.getFullName().trim());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.ROLE_USER);
        user.setEnabled(true);

        User saved = userRepository.save(user);

        String token = tokenProvider.generateTokenFromUsername(saved.getEmail(), saved.getRole().name());

        auditLogService.log("USER_REGISTER", saved.getEmail(), clientIp, "New account registered successfully");

        return new AuthResponse(token, saved.getId(), saved.getEmail(), saved.getFullName(), saved.getRole());
    }

    public AuthResponse login(AuthRequest request, String clientIp) {
        String cleanEmail = request.getEmail().trim().toLowerCase();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(cleanEmail, request.getPassword())
        );

        User user = userRepository.findByEmail(cleanEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!user.isEnabled()) {
            throw new BadRequestException("This account has been deactivated. Please contact security admin.");
        }

        String token = tokenProvider.generateToken(authentication, user.getRole().name());

        auditLogService.log("USER_LOGIN", user.getEmail(), clientIp, "User logged in successfully");

        return new AuthResponse(token, user.getId(), user.getEmail(), user.getFullName(), user.getRole());
    }

    @Transactional(readOnly = true)
    public UserSummaryDto getCurrentUserProfile() {
        String email = SecurityUtils.getCurrentUserEmail()
                .orElseThrow(() -> new BadRequestException("No authenticated user in current session"));

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return new UserSummaryDto(user.getId(), user.getEmail(), user.getFullName(), user.getRole(), user.isEnabled(), user.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public List<UserSummaryDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(u -> new UserSummaryDto(u.getId(), u.getEmail(), u.getFullName(), u.getRole(), u.isEnabled(), u.getCreatedAt()))
                .collect(Collectors.toList());
    }

    @Transactional
    public UserSummaryDto toggleUserStatus(Long userId, String clientIp) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        user.setEnabled(!user.isEnabled());
        User updated = userRepository.save(user);

        auditLogService.log("USER_STATUS_CHANGE", SecurityUtils.getCurrentUserEmail().orElse("ADMIN"), clientIp,
                "User " + user.getEmail() + " status set to enabled=" + user.isEnabled());

        return new UserSummaryDto(updated.getId(), updated.getEmail(), updated.getFullName(), updated.getRole(), updated.isEnabled(), updated.getCreatedAt());
    }
}
