package com.scamshield.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;
import java.sql.Connection;

@Configuration
public class DatabaseConfig {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseConfig.class);

    @Value("${spring.datasource.url:jdbc:mysql://localhost:3306/scamshield?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC}")
    private String mysqlUrl;

    @Value("${spring.datasource.username:root}")
    private String mysqlUsername;

    @Value("${spring.datasource.password:root}")
    private String mysqlPassword;

    @Bean
    @Primary
    public DataSource dataSource() {
        // Attempt MySQL connection first
        try {
            DataSource mysqlDataSource = DataSourceBuilder.create()
                    .driverClassName("com.mysql.cj.jdbc.Driver")
                    .url(mysqlUrl)
                    .username(mysqlUsername)
                    .password(mysqlPassword)
                    .build();

            // Test if connection succeeds
            try (Connection conn = mysqlDataSource.getConnection()) {
                logger.info("Successfully connected to MySQL database: {}", mysqlUrl);
                return mysqlDataSource;
            }
        } catch (Exception ex) {
            logger.warn("==========================================================================");
            logger.warn("NOTICE: MySQL connection attempt failed: {}", ex.getMessage());
            logger.warn("Auto-falling back to High-Performance In-Memory H2 Database (MySQL mode).");
            logger.warn("Configure DB_USERNAME and DB_PASSWORD in environment to use MySQL.");
            logger.warn("==========================================================================");
        }

        // Fallback embedded DataSource
        return DataSourceBuilder.create()
                .driverClassName("org.h2.Driver")
                .url("jdbc:h2:mem:scamshield;DB_CLOSE_DELAY=-1;MODE=MySQL")
                .username("sa")
                .password("")
                .build();
    }
}
